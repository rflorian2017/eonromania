"""
ConfigFlow și OptionsFlow pentru integrarea E·ON România.

Utilizatorul introduce email + parolă, apoi selectează contractele dorite.
Contractele se descoperă automat prin account-contracts/list.
Suportă MFA (Two-Factor Authentication) — dacă e activ, se cere codul OTP.
"""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers import selector
from homeassistant.helpers.selector import (
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
)

from .const import DOMAIN, DEFAULT_UPDATE_INTERVAL, DOMAIN_TOKEN_STORE, CONF_LICENSE_KEY, LICENSE_DATA_KEY
from .api import EonApiClient
from .helpers import (
    build_contract_metadata,
    build_contract_options,
    mask_email,
    resolve_selection,
)

_LOGGER = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Helper comun: fetch contracte după autentificare reușită
# ------------------------------------------------------------------

async def _fetch_contracts_after_login(api: EonApiClient) -> list[dict] | None:
    """Obține lista de contracte după autentificare reușită.

    Returnează lista de contracte sau None dacă nu s-au găsit.
    """
    contracts = await api.async_fetch_contracts_list()
    if contracts and isinstance(contracts, list) and len(contracts) > 0:
        return contracts
    return None


def _store_token(hass, username: str, api: EonApiClient) -> None:
    """Salvează token-ul API în hass.data pentru a fi preluat de __init__.py.

    Token-ul este salvat per username (pot exista mai multe conturi).
    """
    token_data = api.export_token_data()
    if token_data is None:
        return
    store = hass.data.setdefault(DOMAIN_TOKEN_STORE, {})
    store[username.lower()] = token_data
    _LOGGER.debug(
        "Token salvat în hass.data pentru %s (access=%s...).",
        username,
        token_data["access_token"][:8] if token_data.get("access_token") else "None",
    )


# ------------------------------------------------------------------
# ConfigFlow
# ------------------------------------------------------------------

class EonRomaniaConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """ConfigFlow — autentificare + MFA (opțional) + selecție contracte."""

    VERSION = 3

    def __init__(self) -> None:
        self._username: str = ""
        self._password: str = ""
        self._update_interval: int = DEFAULT_UPDATE_INTERVAL
        self._contracts_raw: list[dict] = []
        self._api: EonApiClient | None = None
        # MFA state — salvat la intrarea în pasul MFA, persistent după async_mfa_complete
        self._mfa_type: str = ""
        self._mfa_recipient_display: str = ""

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Pasul 1: Autentificare."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._username = user_input["username"]
            self._password = user_input["password"]
            self._update_interval = user_input.get(
                "update_interval", DEFAULT_UPDATE_INTERVAL
            )

            await self.async_set_unique_id(self._username.lower())
            self._abort_if_unique_id_configured()

            session = async_get_clientsession(self.hass)
            self._api = EonApiClient(session, self._username, self._password)

            if await self._api.async_login():
                # Login reușit fără MFA — salvăm token-ul și obținem contractele
                _store_token(self.hass, self._username, self._api)
                contracts = await _fetch_contracts_after_login(self._api)
                if contracts:
                    self._contracts_raw = contracts
                    return await self.async_step_select_contracts()
                errors["base"] = "no_data"
                _LOGGER.warning(
                    "Autentificare reușită dar nu s-au găsit contracte (utilizator=%s).",
                    self._username,
                )
            elif self._api.mfa_required:
                # MFA necesar — salvăm tipul și destinatarul ACUM (înainte de async_mfa_complete care le șterge)
                mfa_info = self._api.mfa_data or {}
                self._mfa_type = mfa_info.get("type", "EMAIL")
                if self._mfa_type == "EMAIL":
                    self._mfa_recipient_display = mask_email(self._username)
                else:
                    self._mfa_recipient_display = mfa_info.get("recipient", "—")
                _LOGGER.debug(
                    "MFA necesar pentru %s. Tip=%s, Destinatar=%s.",
                    self._username,
                    self._mfa_type,
                    self._mfa_recipient_display,
                )
                return await self.async_step_mfa()
            else:
                errors["base"] = "auth_failed"

        schema = vol.Schema(
            {
                vol.Required("username"): str,
                vol.Required("password"): str,
                vol.Optional(
                    "update_interval", default=DEFAULT_UPDATE_INTERVAL
                ): vol.All(int, vol.Range(min=21600)),
            }
        )

        return self.async_show_form(
            step_id="user", data_schema=schema, errors=errors
        )

    async def async_step_mfa(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Pasul 1b: Introducere cod MFA (Two-Factor Authentication)."""
        errors: dict[str, str] = {}

        if user_input is not None:
            code = user_input.get("code", "").strip()

            if not code:
                errors["base"] = "mfa_invalid_code"
            elif self._api and await self._api.async_mfa_complete(code):
                # MFA completat — salvăm token-ul și obținem contractele
                _store_token(self.hass, self._username, self._api)
                contracts = await _fetch_contracts_after_login(self._api)
                if contracts:
                    self._contracts_raw = contracts
                    return await self.async_step_select_contracts()
                errors["base"] = "no_data"
            else:
                errors["base"] = "mfa_failed"

        # Placeholders din variabilele de instanță (setate la intrarea în MFA, persistente)
        placeholders = {
            "mfa_type": "email" if self._mfa_type == "EMAIL" else "SMS",
            "mfa_recipient": self._mfa_recipient_display or "—",
        }

        schema = vol.Schema(
            {
                vol.Required("code"): str,
            }
        )

        return self.async_show_form(
            step_id="mfa",
            data_schema=schema,
            errors=errors,
            description_placeholders=placeholders,
        )

    async def async_step_select_contracts(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Pasul 2: Selectare contracte din listă."""
        errors: dict[str, str] = {}

        if user_input is not None:
            select_all = user_input.get("select_all", False)
            selected = user_input.get("selected_contracts", [])

            if not select_all and not selected:
                errors["base"] = "no_contract_selected"
            else:
                final_selection = resolve_selection(
                    select_all, selected, self._contracts_raw
                )

                return self.async_create_entry(
                    title=f"E·ON România ({self._username})",
                    data={
                        "username": self._username,
                        "password": self._password,
                        "update_interval": self._update_interval,
                        "select_all": select_all,
                        "selected_contracts": final_selection,
                        "contract_metadata": build_contract_metadata(self._contracts_raw),
                    },
                )

        contract_options = build_contract_options(self._contracts_raw)

        schema = vol.Schema(
            {
                vol.Optional("select_all", default=False): bool,
                vol.Required(
                    "selected_contracts", default=[]
                ): SelectSelector(
                    SelectSelectorConfig(
                        options=contract_options,
                        multiple=True,
                        mode=SelectSelectorMode.LIST,
                    )
                ),
            }
        )

        return self.async_show_form(
            step_id="select_contracts",
            data_schema=schema,
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> EonRomaniaOptionsFlow:
        return EonRomaniaOptionsFlow()


# ------------------------------------------------------------------
# OptionsFlow
# ------------------------------------------------------------------

class EonRomaniaOptionsFlow(config_entries.OptionsFlow):
    """OptionsFlow — modificare setări + selecție contracte + licență."""

    def __init__(self) -> None:
        self._username: str = ""
        self._password: str = ""
        self._update_interval: int = DEFAULT_UPDATE_INTERVAL
        self._contracts_raw: list[dict] = []
        self._api: EonApiClient | None = None
        # MFA state — salvat la intrarea în pasul MFA, persistent după async_mfa_complete
        self._mfa_type: str = ""
        self._mfa_recipient_display: str = ""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Afișează meniul principal cu opțiunile disponibile."""
        return self.async_show_menu(
            step_id="init",
            menu_options=[
                "settings",
                "licenta",
            ],
        )

    async def async_step_licenta(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Formular pentru activarea / vizualizarea licenței EonRomania."""
        from .license import LicenseManager

        errors: dict[str, str] = {}
        description_placeholders: dict[str, str] = {}

        # Obține LicenseManager
        mgr: LicenseManager | None = self.hass.data.get(DOMAIN, {}).get(
            LICENSE_DATA_KEY
        )
        if mgr is None:
            mgr = LicenseManager(self.hass)
            await mgr.async_load()

        # Informații pentru descrierea formularului
        server_status = mgr.status  # 'licensed', 'trial', 'expired', 'unlicensed'

        if server_status == "licensed":
            from datetime import datetime

            tip = mgr.license_type or "necunoscut"
            status_lines = [f"✅ Licență activă ({tip})"]

            if mgr.license_key_masked:
                status_lines[0] += f" — {mgr.license_key_masked}"

            # Data activării
            if mgr.activated_at:
                act_date = datetime.fromtimestamp(
                    mgr.activated_at
                ).strftime("%d.%m.%Y %H:%M")
                status_lines.append(f"Activată la: {act_date}")

            # Data expirării
            if mgr.license_expires_at:
                exp_date = datetime.fromtimestamp(
                    mgr.license_expires_at
                ).strftime("%d.%m.%Y %H:%M")
                status_lines.append(f"📅 Expiră la: {exp_date}")
            elif tip == "perpetual":
                status_lines.append("Valabilitate: nelimitată (perpetuă)")

            description_placeholders["license_status"] = "\n".join(
                status_lines
            )

        elif server_status == "trial":
            description_placeholders["license_status"] = (
                f"⏳ Evaluare — {mgr.trial_days_remaining} zile rămase"
            )
        elif server_status == "expired":
            from datetime import datetime

            status_lines = ["❌ Licență expirată"]

            if mgr.activated_at:
                act_date = datetime.fromtimestamp(
                    mgr.activated_at
                ).strftime("%d.%m.%Y")
                status_lines.append(f"Activată la: {act_date}")
            if mgr.license_expires_at:
                exp_date = datetime.fromtimestamp(
                    mgr.license_expires_at
                ).strftime("%d.%m.%Y")
                status_lines.append(f"Expirată la: {exp_date}")

            description_placeholders["license_status"] = "\n".join(
                status_lines
            )
        else:
            description_placeholders["license_status"] = (
                "❌ Fără licență — funcționalitate blocată"
            )

        if user_input is not None:
            cheie = user_input.get(CONF_LICENSE_KEY, "").strip()

            if not cheie:
                errors["base"] = "license_key_empty"
            elif len(cheie) < 10:
                errors["base"] = "license_key_invalid"
            else:
                # Activare prin API
                result = await mgr.async_activate(cheie)

                if result.get("success"):
                    # Notificare de succes
                    from homeassistant.components import (
                        persistent_notification,
                    )

                    _LICENSE_TYPE_RO = {
                        "monthly": "lunară",
                        "yearly": "anuală",
                        "perpetual": "perpetuă",
                        "trial": "evaluare",
                    }
                    tip_ro = _LICENSE_TYPE_RO.get(
                        mgr.license_type, mgr.license_type or "necunoscut"
                    )

                    persistent_notification.async_create(
                        self.hass,
                        f"Licența E·ON România a fost activată cu succes! "
                        f"Tip: {tip_ro}.",
                        title="Licență activată",
                        notification_id="eonromania_license_activated",
                    )
                    return self.async_create_entry(
                        data=self.config_entry.options
                    )

                # Mapare erori API
                api_error = result.get("error", "unknown_error")
                error_map = {
                    "invalid_key": "license_key_invalid",
                    "already_used": "license_already_used",
                    "expired_key": "license_key_expired",
                    "fingerprint_mismatch": "license_fingerprint_mismatch",
                    "invalid_signature": "license_server_error",
                    "network_error": "license_network_error",
                    "server_error": "license_server_error",
                }
                errors["base"] = error_map.get(api_error, "license_server_error")

        schema = vol.Schema(
            {
                vol.Optional(CONF_LICENSE_KEY): selector.TextSelector(
                    selector.TextSelectorConfig(
                        type=selector.TextSelectorType.TEXT,
                        suffix="EONL-XXXX-XXXX-XXXX-XXXX",
                    )
                ),
            }
        )

        return self.async_show_form(
            step_id="licenta",
            data_schema=schema,
            errors=errors,
            description_placeholders=description_placeholders,
        )

    async def async_step_settings(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Pasul 1: Modificare credențiale."""
        errors: dict[str, str] = {}

        if user_input is not None:
            username = user_input["username"]
            password = user_input["password"]
            update_interval = user_input.get(
                "update_interval", DEFAULT_UPDATE_INTERVAL
            )

            session = async_get_clientsession(self.hass)
            self._api = EonApiClient(session, username, password)

            if await self._api.async_login():
                _store_token(self.hass, username, self._api)
                contracts = await _fetch_contracts_after_login(self._api)
                if contracts:
                    self._contracts_raw = contracts
                    self._username = username
                    self._password = password
                    self._update_interval = update_interval
                    return await self.async_step_select_contracts()
                errors["base"] = "no_data"
            elif self._api.mfa_required:
                # MFA necesar — salvăm credențialele + info MFA ACUM
                self._username = username
                self._password = password
                self._update_interval = update_interval
                mfa_info = self._api.mfa_data or {}
                self._mfa_type = mfa_info.get("type", "EMAIL")
                if self._mfa_type == "EMAIL":
                    self._mfa_recipient_display = mask_email(username)
                else:
                    self._mfa_recipient_display = mfa_info.get("recipient", "—")
                return await self.async_step_mfa()
            else:
                errors["base"] = "auth_failed"

        current = self.config_entry.data

        schema = vol.Schema(
            {
                vol.Required(
                    "username", default=current.get("username", "")
                ): str,
                vol.Required(
                    "password", default=current.get("password", "")
                ): str,
                vol.Required(
                    "update_interval",
                    default=current.get("update_interval", DEFAULT_UPDATE_INTERVAL),
                ): vol.All(int, vol.Range(min=21600)),
            }
        )

        return self.async_show_form(
            step_id="settings", data_schema=schema, errors=errors
        )

    async def async_step_mfa(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Pasul 1b: Introducere cod MFA."""
        errors: dict[str, str] = {}

        if user_input is not None:
            code = user_input.get("code", "").strip()

            if not code:
                errors["base"] = "mfa_invalid_code"
            elif self._api and await self._api.async_mfa_complete(code):
                _store_token(self.hass, self._username, self._api)
                contracts = await _fetch_contracts_after_login(self._api)
                if contracts:
                    self._contracts_raw = contracts
                    return await self.async_step_select_contracts()
                errors["base"] = "no_data"
            else:
                errors["base"] = "mfa_failed"

        # Placeholders din variabilele de instanță (setate la intrarea în MFA, persistente)
        placeholders = {
            "mfa_type": "email" if self._mfa_type == "EMAIL" else "SMS",
            "mfa_recipient": self._mfa_recipient_display or "—",
        }

        schema = vol.Schema(
            {
                vol.Required("code"): str,
            }
        )

        return self.async_show_form(
            step_id="mfa",
            data_schema=schema,
            errors=errors,
            description_placeholders=placeholders,
        )

    async def async_step_select_contracts(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Pasul 2: Modificare selecție contracte."""
        errors: dict[str, str] = {}

        if user_input is not None:
            select_all = user_input.get("select_all", False)
            selected = user_input.get("selected_contracts", [])

            if not select_all and not selected:
                errors["base"] = "no_contract_selected"
            else:
                final_selection = resolve_selection(
                    select_all, selected, self._contracts_raw
                )

                self.hass.config_entries.async_update_entry(
                    self.config_entry,
                    data={
                        "username": self._username,
                        "password": self._password,
                        "update_interval": self._update_interval,
                        "select_all": select_all,
                        "selected_contracts": final_selection,
                        "contract_metadata": build_contract_metadata(self._contracts_raw),
                    },
                )

                await self.hass.config_entries.async_reload(
                    self.config_entry.entry_id
                )

                return self.async_create_entry(data={})

        current = self.config_entry.data

        schema = vol.Schema(
            {
                vol.Optional(
                    "select_all",
                    default=current.get("select_all", False),
                ): bool,
                vol.Required(
                    "selected_contracts",
                    default=current.get("selected_contracts", []),
                ): SelectSelector(
                    SelectSelectorConfig(
                        options=build_contract_options(self._contracts_raw),
                        multiple=True,
                        mode=SelectSelectorMode.LIST,
                    )
                ),
            }
        )

        return self.async_show_form(
            step_id="select_contracts",
            data_schema=schema,
            errors=errors,
        )
