"""adcli test cases"""

from __future__ import annotations

import re

import pytest
from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericADProvider
from sssd_test_framework.roles.samba import Samba
from sssd_test_framework.utils.adcli import AdcliUtils

from .topology import KnownTopology, KnownTopologyGroup


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
    info = client.adcli.info(domain=provider.host.domain, args=["--verbose"])
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
        domain=provider.host.domain,
        login_user=provider.host.adminuser,
        args=[f"--domain-controller={provider.host.hostname}", "--verbose"],
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
        1. Join the client account in the AD
    :steps:
        1. Request information about a client computer account stored in AD-domain
    :expectedresults:
        1. Correct information about the requested client account is fetched from the AD-domain
    """
    client.adcli.join(
        domain=provider.host.domain,
        login_user=provider.host.adminuser,
        args=[f"--domain-controller={provider.host.hostname}", "--verbose"],
        krb=False,
        password=provider.host.adminpw,
    )

    show_computer = client.adcli.show_computer(
        domain=provider.host.domain,
        args=["--login-user", "Administrator", "--verbose"],
        login_user="Administrator",
        krb=False,
        password=provider.host.adminpw,
    )

    short_hostname = client.host.hostname.split(".")[0].upper()
    assert re.findall(
        rf"Retrieved kvno .* for computer account in directory.*CN={short_hostname}",
        show_computer.stderr,
        re.IGNORECASE,
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
        domain=f"{provider.host.domain}",
        login_user=provider.host.adminuser,
        args=["--domain-controller", provider.host.hostname, "--verbose"],
        krb=False,
        password=provider.host.adminpw,
    )

    delete_computer = client.adcli.delete_computer(
        domain=f"{provider.host.domain}",
        args=["--login-user", "Administrator", "--verbose"],
        krb=False,
        login_user="Administrator",
        password=provider.host.adminpw,
    )

    show_computer = client.adcli.show_computer(
        domain=f"{provider.host.domain}",
        args=["--login-user", "Administrator", "--verbose"],
        login_user="Administrator",
        krb=False,
        password=provider.host.adminpw,
    )

    short_hostname = client.host.hostname.split(".")[0].upper()
    assert re.findall(
        rf"Deleted computer account at: CN={short_hostname}", delete_computer.stderr, re.IGNORECASE
    ), "adcli showing computer info"
    assert show_computer.rc != 0, "adcli showing computer info"
    assert re.findall(
        r"No computer account for .* exists", show_computer.stderr, re.IGNORECASE
    ), "adcli showing deleted computer info"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_adcli_testjoin(client: Client, provider: GenericADProvider):
    """
    :title: adcli testjoin AD-domain
    :setup:
        1. Join the client to a AD-domain
    :steps:
        1. Run testjoin to verify check if the client is joined to the AD-domain
    :expectedresults:
        1. The join is active
    """
    client.adcli.join(
        domain=provider.host.domain,
        login_user=provider.host.adminuser,
        args=["--domain-controller", provider.host.hostname, "--verbose"],
        krb=False,
        password=provider.host.adminpw,
    )

    testjoin = client.adcli.testjoin(
        domain=provider.host.domain, args=[f"--domain-controller={provider.host.hostname}", "--verbose"]
    )
    assert testjoin.rc == 0, "client-join is not valid"
    assert re.findall(
        rf"Sucessfully validated join to domain {provider.host.domain}", testjoin.stdout, re.IGNORECASE
    ), "Failed to validate join to domain"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_adcli_join_segfault_389_blocked(client: Client, provider: GenericADProvider):
    """
    :title: adcli join segfault if 389-port blocked
    :setup:
        1. Block 389-UDP port
    :steps:
        1. Join the client account in the AD
    :expectedresults:
        1. No segfault was observed
    """
    client.adcli.join(
        provider.host.domain,
        login_user=provider.host.adminuser,
        args=["--domain-controller", provider.host.hostname, "--verbose"],
        krb=False,
        password=provider.host.adminpw,
    )
    client.firewall.outbound.drop_port(("389", "udp"))


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_adcli_join_with_modified_hostname(client: Client, provider: GenericADProvider):
    """
    :title: adcli join AD-domain with a modified hostname
    :description: Verifies a client can join an AD domain after its hostname has been changed locally.
    :setup:
        1. Modify the client's hostname.
    :steps:
        1. Join the client to the AD-domain using the new hostname.
        2. Verify the computer account was created in AD with the new hostname.
    :expectedresults:
        1. The domain join is successful.
        2. The computer account in AD matches the modified client hostname.
    """
    # Define a new, unique hostname for the client
    new_hostname = "newclient.test"
    hostname_utils = client.hostnameutils
    original_hostname = None

    try:
        # Manually save the original hostname
        original_hostname = hostname_utils.name

        # Change the hostname
        hostname_utils.set_name(new_hostname)

        assert hostname_utils.name == new_hostname
        # Now, attempt to join the domain with the new hostname
        join_command = client.adcli.join(
            domain=provider.host.domain,
            login_user=provider.host.adminuser,
            args=["--domain-controller", provider.host.hostname, "--verbose"],
            krb=False,
            password=provider.host.adminpw,
        )

        ## The computer account name in AD will be the short hostname, uppercased
        new_short_hostname = new_hostname.split(".")[0].upper()

        assert join_command.rc == 0, f"adcli failed to join with modified hostname: {join_command.stderr}"
        assert re.search(
            rf"Retrieved kvno .* for computer account in directory.*CN={new_short_hostname}",
            join_command.stderr,
            re.IGNORECASE,
        ), "Computer account was not created correctly with the modified hostname."

    finally:
        # Ensure the original hostname is always restored
        if original_hostname:
            hostname_utils.set_name(original_hostname)
