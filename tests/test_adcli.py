"""adcli test cases"""

from __future__ import annotations

import pytest
import time
import re


from sssd_test_framework.utils.adcli import AdcliUtils
from .topology import KnownTopology, KnownTopologyGroup
from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.samba import Samba
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericADProvider


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_adcli_info(client: Client, provider: GenericADProvider):
    """
    :title: adcli look up a AD-domain
    :steps:
        1. Query a specified AD-domain
    :expectedresults:
        1. AD-domain information is properly fetched
    """
    info = client.adcli.info(provider.host.domain, args=["--verbose"])
    assert info.rc == 0, "adcli info command failed!"
    assert provider.host.domain in info.stderr, "adcli failed to fetch domain info!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_adcli_join(client: Client, provider: GenericADProvider):
    """
    :title: adcli join AD-domain
    :steps:
        1. Join the client to a AD-domain
    :expectedresults:
        1. A computer account and related keytabs of client should be created on AD-domain
    """
    join_command = client.adcli.join(
        provider.host.domain,
        login_user=provider.host.adminuser,
        args=["--domain-controller", provider.host.hostname, "--verbose"],
        krb=False,
        password=provider.host.adminpw,
    )
    short_hostname = client.host.hostname.split(".")[0].upper()
    assert join_command.rc == 0, "adcli failed to join the client"
    assert re.findall(
        rf"Retrieved kvno .* for computer account in directory.*CN={short_hostname}",
        join_command.stderr,
        re.IGNORECASE,
    ), "adcli failed to join the client"
    assert re.findall(
        rf"Added the entries to the keytab: host.{short_hostname}.* FILE:/etc/krb5.keytab",
        join_command.stderr,
        re.IGNORECASE,
    ), "adcli failed to join the client"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_adcli_show_computer(client: Client, provider: GenericADProvider):
    """
    :title: adcli show computer
    :setup:
        1. join the client account in the ad
    :steps:
        1. Request information about a client computer account stored in AD-domain
    :expectedresults:
        1. Correct information about the requested client account is fetched from the AD-domain
    """
    client.adcli.join(
        provider.host.domain,
        login_user=provider.host.adminuser,
        args=["--domain-controller", provider.host.hostname, "--verbose"],
        krb=False,
        password=provider.host.adminpw,
    )

    show_computer = client.adcli.show_computer(
        provider.host.domain,
        args=["--verbose"],
        login_user="Administrator",
        krb=False,
        password=provider.host.adminpw,
    )

    short_hostname = client.host.hostname.split(".")[0].upper()
    assert re.findall(
        rf"Retrieved kvno .* for computer account in directory.*CN={short_hostname}", show_computer.stderr
    ), "adcli failed to show computer info"
    assert show_computer.rc == 0, "adcli failed showing computer info"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_adcli_delete_computer(client: Client, provider: GenericADProvider):
    """
    :title: adcli delete computer
    :setup:
        1. Join the client account in the AD
    :steps:
        1. Delete a client computer account from the AD-domain
    :expectedresults:
        1. Requested client computer account is correctly deleted from AD-Domain
    """
    client.adcli.join(
        provider.host.domain,
        login_user=provider.host.adminuser,
        args=["--domain-controller", provider.host.hostname, "--verbose"],
        krb=False,
        password=provider.host.adminpw,
    )

    delete_computer = client.adcli.delete_computer(
        provider.host.domain,
        args=["--domain=" f"{provider.host.domain}", "--login-user", "Administrator", "--verbose"],
        krb=False,
        login_user="Administrator",
        password=provider.host.adminpw,
    )

    show_computer = client.adcli.show_computer(
        provider.host.domain,
        args=["--verbose"],
        login_user="Administrator",
        krb=False,
        password=provider.host.adminpw,
    )

    short_hostname = client.host.hostname.split(".")[0].upper()
    assert re.findall(
        rf"Deleted computer account at: CN={short_hostname}", delete_computer.stderr
    ), "adcli showing computer info"
    assert show_computer.rc != 0, "adcli showing computer info"
    assert re.findall(
        r"No computer account for .* exists", show_computer.stderr
    ), "adcli showing deleted computer info"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_adcli_join_ldaps(client: Client, provider: GenericADProvider):
    """
    :title: adcli join AD-domain over ldaps
    :setup:
        1. Block outbound traffic through 389 port on client
    :steps:
        1. Join the client to a AD-domain
    :expectedresults:
        1. A computer account and related keytabs of client should be created on AD-domain
    """
    client.firewall.outbound.accept_port(636)
    client.firewall.outbound.reject_port(389)
    join_command = client.adcli.join(
        provider.host.domain,
        login_user=provider.host.adminuser,
        args=["--use-ldaps", "--domain-controller", provider.host.hostname, "--verbose"],
        krb=False,
        password=provider.host.adminpw,
    )
    short_hostname = client.host.hostname.split(".")[0].upper()
    assert join_command.rc == 0, "adcli failed to join the client"
    assert re.findall(
        rf"Retrieved kvno .* for computer account in directory.*CN={short_hostname}",
        join_command.stderr,
        re.IGNORECASE,
    ), "adcli failed to join the client"
    assert re.findall(
        rf"Added the entries to the keytab: host.{short_hostname}.* FILE:/etc/krb5.keytab",
        join_command.stderr,
        re.IGNORECASE,
    ), "adcli failed to join the client"
