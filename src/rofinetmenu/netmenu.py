#!/usr/bin/env python
# encoding:utf8

import locale
import os
import sys
import uuid
import configparser

from enum import Flag
from subprocess import Popen, PIPE
from xdg.BaseDirectory import xdg_config_home

import gi
gi.require_version('NM', '1.0')
from gi.repository import NM, GLib


class ConnectionFlags(Flag):
    NONE = 0
    WIFI = 1
    ETHERNET = 2
    WIFI_AND_ETHERNET = WIFI | ETHERNET


class Config:
    config = configparser.ConfigParser()
    cmd = None
    default_wifi_device = None
    default_ethernet_device = None
    print_config_menu = True
    user_local_password = True
    active_devices = ConnectionFlags.WIFI
    hide_password = True

    def __init__(self, path, extra_config_args):
        self.__read_config(path, extra_config_args)

    def get_default_device(self, type):
        if type == NM.DeviceType.WIFI:
            return self.default_wifi_device
        elif type == NM.DeviceType.ETHERNET:
            return self.default_ethernet_device

        return None

    def get_launcher_cmd(self):
        return list(self.cmd)

    def __read_config(self, path=None, extra_config_args=None):  # TODO: Take extra args in account
        self.cmd = []
        self.cmd.extend(['rofi', '-dmenu'])

        if not path: # Default path
            path = os.path.join(xdg_config_home, "rofi-net-menu/config")

        self.config.read(path)

        if not self.config.sections():
            return

        if self.config.has_section('launcher'):
            args = dict(self.config.items('launcher'))

            if 'theme' in args:
                theme = args['theme']
                self.cmd.extend(['-config', theme])

            case_insensitive = True
            if 'case_insensitive' in args:
                if not self.config.getboolean('launcher', 'case_insensitive'):
                    case_insensitive = False

            if case_insensitive:
                self.cmd.append("-i")

            if 'hide_password' in args:
                if not self.config.getboolean('launcher', 'hide_password'):
                    self.hide_password = False

        if self.config.has_section('general'):
            args = dict(self.config.items('general'))
            if 'default_wifi_device' in args:
                self.default_wifi_device = args['default_wifi_device']
            if 'default_ethernet_device' in args:
                self.default_ethernet_device = args['default_ethernet_device']
            if 'print_config_menu' in args:
                self.print_config_menu = args['print_config_menu']
            if 'print_ethernet' in args:
                if self.config.getboolean('general', 'print_ethernet'):
                    self.active_devices |= ConnectionFlags.ETHERNET
                else:
                    self.active_devices &= ~ConnectionFlags.ETHERNET
            if 'print_wifi' in args:
                if self.config.getboolean('general', 'print_wifi'):
                    self.active_devices |= ConnectionFlags.WIFI
                else:
                    self.active_devices &= ~ConnectionFlags.WIFI
            if 'user_local_password' in args:
                self.user_local_password = self.config.getboolean('general', 'user_local_password')


class MenuEntry:
    entry_name = None
    callback = None
    args = None

    def __init__(self, entry_name, callback, args=None,):
        self.entry_name = entry_name
        self.callback = callback

        if args is None:
            self.args = None
        elif isinstance(args, list):
            self.args = args
        else:
            self.args = [args]

    def __str__(self):
        return self.entry_name

    def __call__(self):
        if self.args is None:
            self.callback()
        else:
            self.callback(*self.args)


class AbstractEntriesGenerator:
    client = None
    device = None
    config = None

    def __init__(self, client, config):
        self.client = client
        self.config = config

    def _choose_device(self, type):
        devices = self.client.get_devices()
        devices = [d for d in devices if d.get_device_type() == type]

        default_device = self.config.get_default_device(type)
        if default_device:
            self.device = default_device
        else:
            # TODO: Choose device with rofi
            self.device = devices[0]


class EthernetEntriesGenerator(AbstractEntriesGenerator):
    connections = None
    active_connections = None

    def __init__(self, client, config):
        self.connections = client.get_connections()
        self.active_connections = client.get_active_connections()
        super(EthernetEntriesGenerator, self).__init__(client, config)

    def choose_device(self):
        self._choose_device(NM.DeviceType.ETHERNET)

    def is_valid_connection(self, connection):
        if connection.get_setting_wired():
            return connection.get_setting_wired().get_mac_address() \
                   == self.device.get_permanent_hw_address() or not connection.get_setting_wired().get_mac_address()

        return False

    def create_entries(self):
        connections = self.client.get_connections()

        active_connection = self.device.get_active_connection()

        entries = []
        active_lines = []
        for connection in connections:
            if self.is_valid_connection(connection):
                is_active = connection == active_connection
                entries.append(MenuEntry(connection.get_id(),
                                         self.process_entry, args=[connection, is_active]))
                if connection == active_connection:
                    active_lines.append(len(entries) - 1)

        return entries, active_lines

    def process_entry(self, selection, is_active):
        if is_active:
            self.client.deactivate_connection_async(selection)
        else:
            self.client.activate_connection_async(selection)


class WifiEntriesGenerator(AbstractEntriesGenerator):
    connections = None
    active_connections = None
    active_ap = None
    glib_mainloop = GLib.MainLoop()

    def __init__(self, client, config):
        super(WifiEntriesGenerator, self).__init__(client, config)

        self.connections = self.client.get_connections()
        self.active_connections = self.client.get_active_connections()

    def choose_device(self):
        self._choose_device(NM.DeviceType.WIFI)

    @staticmethod
    def ssid_to_utf8(ap):
        ssid = ap.get_ssid()
        if not ssid:
            return ""
        return NM.utils_ssid_to_utf8(ap.get_ssid().get_data())

    @staticmethod
    def get_security(ap):
        flags = ap.get_flags()
        wpa_flags = ap.get_wpa_flags()
        rsn_flags = ap.get_rsn_flags()

        str = ""
        if ((flags & getattr(NM, '80211ApFlags').PRIVACY) and
                (wpa_flags == 0) and (rsn_flags == 0)):
            str += " WEP"
        if wpa_flags != 0:
            str += " WPA1"
        if rsn_flags != 0:
            str += " WPA2"
        if ((wpa_flags & getattr(NM, '80211ApSecurityFlags').KEY_MGMT_802_1X) or
                (rsn_flags & getattr(NM, '80211ApSecurityFlags').KEY_MGMT_802_1X)):
            str += " 802.1X"

        if not str:
            str += "/"

        return str

    def get_passphrase(self):
        cmd = self.config.get_launcher_cmd()
        cmd.extend(['-p', 'Password', '-l', '0'])

        if self.config.hide_password:
            cmd.append('-password')

        return Popen(cmd, stdin=PIPE, stdout=PIPE).communicate()[0].decode(locale.getpreferredencoding())

    def create_profile(self, access_point, password=""):
        password = str(password).strip()
        access_point_security = WifiEntriesGenerator.get_security(access_point)

        profile = NM.SimpleConnection.new()
        s_con = NM.SettingConnection.new()
        s_con.set_property(NM.SETTING_CONNECTION_ID, WifiEntriesGenerator.ssid_to_utf8(access_point))
        s_con.set_property(NM.SETTING_CONNECTION_UUID, str(uuid.uuid4()))
        s_con.set_property(NM.SETTING_CONNECTION_TYPE, NM.SETTING_WIRELESS_SETTING_NAME)
        profile.add_setting(s_con)

        s_wifi = NM.SettingWireless.new()
        s_wifi.set_property(NM.SETTING_WIRELESS_SSID, access_point.get_ssid())
        s_wifi.set_property(NM.SETTING_WIRELESS_MODE, NM.SETTING_WIRELESS_MODE_INFRA)
        profile.add_setting(s_wifi)

        s_ip4 = NM.SettingIP4Config.new()
        s_ip4.set_property(NM.SETTING_IP_CONFIG_METHOD, NM.SETTING_IP4_CONFIG_METHOD_AUTO)
        profile.add_setting(s_wifi)

        s_ip6 = NM.SettingIP6Config.new()
        s_ip6.set_property(NM.SETTING_IP_CONFIG_METHOD, NM.SETTING_IP6_CONFIG_METHOD_AUTO)
        profile.add_setting(s_ip6)

        if access_point_security != "/":
            s_wifi_security = NM.SettingWirelessSecurity.new()
            if "WPA" in access_point_security:
                s_wifi_security.set_property(NM.SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk")
                s_wifi_security.set_property(NM.SETTING_WIRELESS_SECURITY_AUTH_ALG, "open")

                if self.config.user_local_password:
                    s_wifi_security.set_property(NM.SETTING_WIRELESS_SECURITY_PSK_FLAGS, "1")

                s_wifi_security.set_property(NM.SETTING_WIRELESS_SECURITY_PSK, password)

            elif "WEP" in access_point_security:
                s_wifi_security.set_property(NM.SETTING_WIRELESS_SECURITY_KEY_MGMT, "None")
                s_wifi_security.set_property(NM.SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, NM.WepKeyType.PASSPHRASE)
                s_wifi_security.set_wep_key(0, password)

            profile.add_setting(s_wifi_security)

        return profile

    def create_ap_list(self):
        aps = {}
        self.active_ap = self.device.get_active_access_point()
        ap_list = sorted(self.device.get_access_points(),
                         key=lambda access_point: access_point.get_strength(), reverse=True)

        current_connections = [connection for connection in self.connections if
                               connection.get_setting_wireless() is not None and
                               connection.get_setting_wireless().get_mac_address() ==
                               self.device.get_permanent_hw_address()]

        filtered_connections = []
        active_ap_name = None

        if self.active_ap:
            filtered_connections = self.active_ap.filter_connections(current_connections)
            active_ap_name = WifiEntriesGenerator.ssid_to_utf8(self.active_ap)

        active_ap_connection = [active_connection for active_connection in self.active_connections
                                if active_connection.get_connection() in filtered_connections]

        if len(active_ap_connection) > 1:
            raise ValueError("Multiple connection profiles match the wireless access point")

        active_ap_connection = active_ap_connection[0] if active_ap_connection else None

        for ap in ap_list:
            ap_name = WifiEntriesGenerator.ssid_to_utf8(ap)

            if ap != self.active_ap and ap_name == active_ap_name:
                continue

            if ap_name not in aps:
                aps[ap_name] = ap

        return aps, active_ap_connection

    def create_entries(self):
        aps, active_ap_connection = self.create_ap_list()
        active_ap_bssid = self.active_ap.get_bssid() if self.active_ap is not None else ""

        max_name_leng = max([len(name) for name in aps]) if aps else 0
        security_strs = [WifiEntriesGenerator.get_security(ap) for _, ap in aps.items()]
        max_security_len = max([len(sec) for sec in security_strs]) if security_strs else 0

        actions = []
        active_lines = []
        for name, ap, sec in zip(aps.keys(), aps.values(), security_strs):
            bars = NM.utils_wifi_strength_bars(ap.get_strength())

            is_active = ap.get_bssid() == active_ap_bssid
            entry_str = u"{:<{}s}  {:<{}s}  {}".format(name, max_name_leng, sec,
                                                       max_security_len, bars)

            if is_active:
                actions.append(MenuEntry(entry_str, self.process_entry, args=[active_ap_connection, True]))
                active_lines.append(len(actions) - 1)
            else:
                actions.append(MenuEntry(entry_str, self.process_entry, args=[ap, False]))

        return actions, active_lines

    def process_entry(self, selection, is_active):
        if is_active:
            self.client.deactivate_connection_async(selection)
        else:
            current_connections = [i for i in self.connections if
                                   i.get_setting_wireless() is not None and
                                   i.get_setting_wireless().get_mac_address() ==
                                   self.device.get_permanent_hw_address()]
            connection = selection.filter_connections(current_connections)

            if len(connection) > 1:
                raise ValueError("There are multiple connections possible")

            if len(connection) == 1:
                self.client.activate_connection_async(connection[0])
            else:
                if WifiEntriesGenerator.get_security(selection) != "/":
                    password = self.get_passphrase()
                else:
                    password = ""

                profile = self.create_profile(selection, password)
                self.client.add_and_activate_connection_async(profile, self.device, selection.get_path(),
                                                              None, self.verify_connection, profile)

                self.glib_mainloop.run()

    def verify_connection(self, client, result, data):
        try:
            act_conn = client.add_and_activate_connection_finish(result)
            conn = act_conn.get_connection()
            conn.verify()
            conn.verify_secrets()
            data.verify()
            data.verify_secrets()
        except GLib.Error:
            try:
                conn.delete()
            except UnboundLocalError:
                pass
        finally:
            self.glib_mainloop.quit()


class SettingEntriesGenerator(AbstractEntriesGenerator):
    def __init__(self, client, config):
        super(SettingEntriesGenerator, self).__init__(client, config)

    def create_entries(self):
        networking_entry = "Disable" if self.client.networking_get_enabled() else "Enable"
        networking_entry += " Networking"

        wifi_entry = "Disable" if self.client.wireless_get_enabled() else "Enable"
        wifi_entry += " Wifi"

        return ([MenuEntry(networking_entry, self.toggle_networking, args=[not self.client.networking_get_enabled()]),
                 MenuEntry(wifi_entry, self.toggle_wifi, args=[not self.client.wireless_get_enabled()])], [])

    def toggle_networking(self, enable):
        self.client.networking_set_enabled(enable)

    def toggle_wifi(self, enable):
        self.client.wireless_set_enabled(enable)


class NetworkMenu:
    eeg = None
    weg = None
    seg = None
    config = None

    def __init__(self, config_path, command_line_args):
        client = NM.Client.new(None)
        self.config = Config(config_path, command_line_args)
        self.eeg = EthernetEntriesGenerator(client, self.config)
        self.weg = WifiEntriesGenerator(client, self.config)
        self.seg = SettingEntriesGenerator(client, self.config)

    def display_choose_device(self):
        active_devices = self.config.active_devices

        if active_devices & ConnectionFlags.WIFI:
            self.weg.choose_device()
        if active_devices & ConnectionFlags.ETHERNET:
            self.eeg.choose_device()

    @staticmethod
    def __merge_entries(entries, new_entries, empty_entry):
        if new_entries[0]:
            nbr_entries = len(entries[0])
            entries[0].extend(new_entries[0])
            entries[1].extend([e + nbr_entries for e in new_entries[1]])

            if empty_entry:
                entries[0].append(empty_entry)

    def __create_wifi_entries(self, entries, empty_entry):
        self.__merge_entries(entries, self.weg.create_entries(), empty_entry)

    def __create_eth_entries(self, entries, empty_entry):
        self.__merge_entries(entries, self.eeg.create_entries(), empty_entry)

    def __create_settings_entries(self, entries, empty_entry):
        self.__merge_entries(entries, self.seg.create_entries(), empty_entry)

    def get_user_selection(self, actions, active_lines):
        command = self.config.get_launcher_cmd()
        command.extend(['-p', 'Network'])

        if active_lines:
            command.extend(["-a", ",".join([str(num) for num in active_lines])])

        command.append("-lines")
        command.append(str(len(actions)))

        inp_bytes = "\n".join([str(i) for i in actions]).encode(locale.getpreferredencoding())

        ENV = os.environ.copy()
        ENV['LC_ALL'] = 'C'

        sel = Popen(command, stdin=PIPE, stdout=PIPE,
                    env=ENV).communicate(input=inp_bytes)[0].decode(locale.getpreferredencoding())

        if not sel.rstrip():
            sys.exit()

        action_idx = [i for i in actions
                      if str(i).strip() == sel.strip()]

        assert len(action_idx) == 1

        return action_idx[0]

    def display_menu(self):
        empty_entry = MenuEntry("", None)
        menu_entries = ([], [])

        active_devices = self.config.active_devices

        if active_devices & ConnectionFlags.WIFI:
            self.__create_wifi_entries(menu_entries, empty_entry)
        if active_devices & ConnectionFlags.ETHERNET:
            self.__create_eth_entries(menu_entries, empty_entry)

        self.__create_settings_entries(menu_entries, None)

        selection = self.get_user_selection(*menu_entries)
        selection()


def main():
    locale.setlocale(locale.LC_ALL, '')
    nm = NetworkMenu(None, None)

    nm.display_choose_device()
    nm.display_menu()


if __name__ == "__main__":
    main()
