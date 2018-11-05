import os

from vpp_papi import VPP
import fnmatch
import os
import json
import binascii

class VppPapiProvider(object):
    """VPP-api provider using vpp-papi
    """

    def __init__(self):
        jsonfiles = []
        install_dir = '/usr/share/vpp/api/'
        for root, dirnames, filenames in os.walk(install_dir):
            for filename in fnmatch.filter(filenames, '*.api.json'):
                jsonfiles.append(os.path.join(root, filename))

        self.vpp = VPP(jsonfiles)
        self.vpp.connect('vpp_agent_test')
        self.papi = self.vpp.api


    def __exit__(self, exc_type, exc_value, traceback):
        self._expect_api_retval = self._expect_stack.pop()
        self.vpp.disconnect()

    def disconnect(self):
        """Disconnect the API from VPP"""
        self.vpp.disconnect()

    def convert_reply(self, api_r):
        """Process API reply / a part of API reply for smooth converting to
        JSON string.

        Apply binascii.hexlify() method for string values.
        :param api_r: API reply.
        :type api_r: Vpp_serializer reply object
        :returns: Processed API reply / a part of API reply.
        :rtype: dict
        """
        unwanted_fields = ['count', 'index']

        reply_dict = dict()
        reply_key = repr(api_r).split('(')[0]
        reply_value = dict()
        for item in dir(api_r):
            if not item.startswith('_') and item not in unwanted_fields:
                attr_value = getattr(api_r, item)
                value = binascii.hexlify(attr_value) \
                    if isinstance(attr_value, str) else attr_value
                reply_value[item] = value
        reply_dict[reply_key] = reply_value
        return reply_dict

    def process_reply(self, api_reply):
        """Process API reply for smooth converting to JSON string.

        :param api_reply: API reply.
        :type api_reply: Vpp_serializer reply object or list of vpp_serializer
            reply objects
        :returns: Processed API reply.
        :rtype: list or dict
        """

        if isinstance(api_reply, list):
            converted_reply = list()
            for r in api_reply:
                converted_reply.append(self.convert_reply(r))
        else:
            converted_reply = self.convert_reply(api_reply)
        return converted_reply

    def api(self, api_fn, api_args, expected_retval=0):
        """ Call API function and check it's return value.
        Call the appropriate hooks before and after the API call
        :param api_fn: API function to call
        :param api_args: tuple of API function arguments
        :param expected_retval: Expected return value (Default value = 0)
        :returns: reply from the API
        """
        reply = api_fn(**api_args)
        json_reply = self.process_reply(reply)

        return json_reply

    def sw_interface_dump(self, filter=None):
        """
        :param filter:  (Default value = None)
        """
        if filter is not None:
            args = {"name_filter_valid": 1, "name_filter": filter}
        else:
            args = {}
        return self.api(self.papi.sw_interface_dump, args)

    def ip_unnumbered_dump(self, sw_if_index=0xffffffff):
        return self.api(self.papi.ip_unnumbered_dump,
                        {'sw_if_index': sw_if_index})

    def bridge_domain_dump(self, bd_id=0):
        """
        :param int bd_id: Bridge domain ID. (Default value = 0 => dump of all
            existing bridge domains returned)
        :return: Dictionary of bridge domain(s) data.
        """
        return self.api(self.papi.bridge_domain_dump,
                        {'bd_id': bd_id})

    def ip_fib_dump(self):
        return self.api(self.papi.ip_fib_dump, {})

    def ip6_fib_dump(self):
        return self.api(self.papi.ip6_fib_dump, {})

    def ip_neighbor_dump(self,
                         sw_if_index,
                         is_ipv6=0):
        """ Return IP neighbor dump.
        :param sw_if_index:
        :param int is_ipv6: 1 for IPv6 neighbor, 0 for IPv4. (Default = 0)
        """

    def ip_dump(self,
                is_ipv6=0,
                ):
        """ Return IP dump.
        :param int is_ipv6: 1 for IPv6 neighbor, 0 for IPv4. (Default = 0)
        """

        return self.api(
            self.papi.ip_dump,
            {'is_ipv6': is_ipv6,
             }
        )

    def udp_encap_dump(self):
        return self.api(self.papi.udp_encap_dump, {})

    def mpls_fib_dump(self):
        return self.api(self.papi.mpls_fib_dump, {})

    def mpls_tunnel_dump(self, sw_if_index=0xffffffff):
        return self.api(self.papi.mpls_tunnel_dump,
                        {'sw_if_index': sw_if_index})

    def nat44_address_dump(self):
        """Dump NAT44 addresses
        :return: Dictionary of NAT44 addresses
        """
        return self.api(self.papi.nat44_address_dump, {})

    def nat44_interface_dump(self):
        """Dump interfaces with NAT44 feature
        :return: Dictionary of interfaces with NAT44 feature
        """
        return self.api(self.papi.nat44_interface_dump, {})

    def nat44_interface_output_feature_dump(self):
        """Dump interfaces with NAT44 output feature
        :return: Dictionary of interfaces with NAT44 output feature
        """
        return self.api(self.papi.nat44_interface_output_feature_dump, {})

    def nat44_static_mapping_dump(self):
        """Dump NAT44 static mappings
        :return: Dictionary of NAT44 static mappings
        """
        return self.api(self.papi.nat44_static_mapping_dump, {})

    def nat44_identity_mapping_dump(self):
        """Dump NAT44 identity mappings
        :return: Dictionary of NAT44 identity mappings
        """
        return self.api(self.papi.nat44_identity_mapping_dump, {})

    def nat44_interface_addr_dump(self):
        """Dump NAT44 addresses interfaces
        :return: Dictionary of NAT44 addresses interfaces
        """
        return self.api(self.papi.nat44_interface_addr_dump, {})

    def nat44_user_session_dump(
            self,
            ip_address,
            vrf_id):
        """Dump NAT44 user's sessions
        :param ip_address: ip adress of the user to be dumped
        :param cpu_index: cpu_index on which the user is
        :param vrf_id: VRF ID
        :return: Dictionary of S-NAT sessions
        """
        return self.api(
            self.papi.nat44_user_session_dump,
            {'ip_address': ip_address,
             'vrf_id': vrf_id})

    def nat44_user_dump(self):
        """Dump NAT44 users
        :return: Dictionary of NAT44 users
        """
        return self.api(self.papi.nat44_user_dump, {})

    def nat44_lb_static_mapping_dump(self):
        """Dump NAT44 load balancing static mappings
        :return: Dictionary of NAT44 load balancing static mapping
        """
        return self.api(self.papi.nat44_lb_static_mapping_dump, {})

    def nat_reass_dump(self):
        """Dump NAT virtual fragmentation reassemblies
        :return: Dictionary of NAT virtual fragmentation reassemblies
        """
        return self.api(self.papi.nat_reass_dump, {})

    def nat_det_map_dump(self):
        """Dump deterministic NAT mappings
        :return: Dictionary of deterministic NAT mappings
        """
        return self.api(self.papi.nat_det_map_dump, {})

    def nat_det_session_dump(
            self,
            user_addr):
        """Dump deterministic NAT sessions belonging to a user
        :param user_addr - inside IP address of the user
        :return: Dictionary of deterministic NAT sessions
        """
        return self.api(
            self.papi.nat_det_session_dump,
            {'is_nat44': 1,
             'user_addr': user_addr})

    def nat64_pool_addr_dump(self):
        """Dump NAT64 pool addresses
        :return: Dictionary of NAT64 pool addresses
        """
        return self.api(self.papi.nat64_pool_addr_dump, {})

    def nat64_interface_dump(self):
        """Dump interfaces with NAT64 feature
        :return: Dictionary of interfaces with NAT64 feature
        """
        return self.api(self.papi.nat64_interface_dump, {})

    def nat64_bib_dump(self, protocol=255):
        """Dump NAT64 BIB
        :param protocol: IP protocol (Default value = 255, all BIBs)
        :returns: Dictionary of NAT64 BIB entries
        """
        return self.api(self.papi.nat64_bib_dump, {'proto': protocol})

    def nat64_st_dump(self, protocol=255):
        """Dump NAT64 session table
        :param protocol: IP protocol (Default value = 255, all STs)
        :returns: Dictionary of NAT64 sesstion table entries
        """
        return self.api(self.papi.nat64_st_dump, {'proto': protocol})

    def nat64_prefix_dump(self):
        """Dump NAT64 prefix
        :returns: Dictionary of NAT64 prefixes
        """
        return self.api(self.papi.nat64_prefix_dump, {})

    def nat66_interface_dump(self):
        """Dump interfaces with NAT66 feature
        :return: Dictionary of interfaces with NAT66 feature
        """
        return self.api(self.papi.nat66_interface_dump, {})

    def nat66_static_mapping_dump(self):
        """Dump NAT66 static mappings
        :return: Dictionary of NAT66 static mappings
        """
        return self.api(self.papi.nat66_static_mapping_dump, {})

    def bfd_udp_session_dump(self):
        return self.api(self.papi.bfd_udp_session_dump, {})

    def bfd_auth_keys_dump(self):
        return self.api(self.papi.bfd_auth_keys_dump, {})

    def dhcp_client_dump(self):
        return self.api(self.papi.dhcp_client_dump, {})

    def mfib_signal_dump(self):
        return self.api(self.papi.mfib_signal_dump, {})

    def ip_mfib_dump(self):
        return self.api(self.papi.ip_mfib_dump, {})

    def ip6_mfib_dump(self):
        return self.api(self.papi.ip6_mfib_dump, {})

    def lisp_locator_set_dump(self):
        return self.api(self.papi.lisp_locator_set_dump, {})


    def lisp_locator_dump(self, is_index_set, ls_name=None, ls_index=0):
        return self.api(
            self.papi.lisp_locator_dump,
            {
                'is_index_set': is_index_set,
                'ls_name': ls_name,
                'ls_index': ls_index,
            })

    def lisp_eid_table_dump(self,
                            eid_set=0,
                            prefix_length=0,
                            vni=0,
                            eid_type=0,
                            eid=None,
                            filter_opt=0):
        return self.api(
            self.papi.lisp_eid_table_dump,
            {
                'eid_set': eid_set,
                'prefix_length': prefix_length,
                'vni': vni,
                'eid_type': eid_type,
                'eid': eid,
                'filter': filter_opt,
            })

    def vxlan_gbp_tunnel_dump(self, sw_if_index=0xffffffff):
        return self.api(self.papi.vxlan_gbp_tunnel_dump,
                        {'sw_if_index': sw_if_index})

    def acl_dump(self, acl_index, expected_retval=0):
        return self.api(self.papi.acl_dump,
                        {'acl_index': acl_index},
                        expected_retval=expected_retval)

    def acl_interface_list_dump(self, sw_if_index=0xFFFFFFFF,
                                expected_retval=0):
        return self.api(self.papi.acl_interface_list_dump,
                        {'sw_if_index': sw_if_index},
                        expected_retval=expected_retval)


    def macip_acl_dump(self, acl_index=4294967295):
        """ Return MACIP acl dump
        """
        return self.api(
            self.papi.macip_acl_dump, {'acl_index': acl_index})

    def bier_table_dump(self):
        return self.api(self.papi.bier_table_dump, {})

    def bier_route_dump(self, bti):
        return self.api(
            self.papi.bier_route_dump,
            {'br_tbl_id': {"bt_set": bti.set_id,
                           "bt_sub_domain": bti.sub_domain_id,
                           "bt_hdr_len_id": bti.hdr_len_id}})

    def bier_imp_dump(self):
        return self.api(self.papi.bier_imp_dump, {})

    def bier_disp_table_dump(self):
        return self.api(self.papi.bier_disp_table_dump, {})

    def bier_disp_entry_dump(self, bdti):
        return self.api(
            self.papi.bier_disp_entry_dump,
            {'bde_tbl_id': bdti})

    def gbp_endpoint_dump(self):
        """ GBP endpoint Dump """
        return self.api(self.papi.gbp_endpoint_dump, {})

    def gbp_endpoint_group_dump(self):
        """ GBP endpoint group Dump """
        return self.api(self.papi.gbp_endpoint_group_dump, {})

    def gbp_recirc_dump(self):
        """ GBP recirc Dump """
        return self.api(self.papi.gbp_recirc_dump, {})



    def gbp_subnet_dump(self):
        """ GBP Subnet Dump """
        return self.api(self.papi.gbp_subnet_dump, {})

    def gbp_contract_dump(self):
        """ GBP contract Dump """
        return self.api(self.papi.gbp_contract_dump, {})


    def igmp_dump(self, sw_if_index=None):
        """ Dump all (S,G) interface configurations """
        if sw_if_index is None:
            sw_if_index = 0xffffffff
        return self.api(self.papi.igmp_dump,
                        {'sw_if_index': sw_if_index})


    def sw_interface_slave_dump(
            self,
            sw_if_index):
        """
        :param sw_if_index: bond sw_if_index
        """
        return self.api(self.papi.sw_interface_slave_dump,
                        {'sw_if_index': sw_if_index})

    def sw_interface_bond_dump(
            self):
        """
        """
        return self.api(self.papi.sw_interface_bond_dump,
                        {})

    def sw_interface_vhost_user_dump(
            self):
        """
        """
        return self.api(self.papi.sw_interface_vhost_user_dump,
                        {})

    def abf_policy_dump(self):
        return self.api(
            self.papi.abf_policy_dump, {})

    def abf_itf_attach_dump(self):
        return self.api(
            self.papi.abf_itf_attach_dump, {})

    def pipe_dump(self):
        return self.api(self.papi.pipe_dump, {})

    def memif_dump(self):
        return self.api(self.papi.memif_dump, {})

    def memif_socket_filename_dump(self):
        return self.api(self.papi.memif_socket_filename_dump, {})

    def svs_dump(self):
        return self.api(self.papi.svs_dump, {})

