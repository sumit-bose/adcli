"""
Tests for adcli join with various computer names.
"""

from __future__ import annotations

import pytest
import re
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericADProvider
from .topology import KnownTopologyGroup


def generate_test_names(hostname: str) -> list[str]:
    """Generates a list of computer names to test based on the hostname."""
    # Truncate to 10 chars to leave room for modifications
    base_name = hostname[:10]

    upper = base_name.upper()
    lower = base_name.lower()

    # Generate a digit-based name (simple hash-like)
    digits = "".join([str(ord(c) % 10) for c in base_name])

    names = [
        upper,
        lower,
        digits,
        upper.capitalize(),     # Mixed case 1
        lower.capitalize(),     # Mixed case 2
    ]

    # Add names with separators if length permits
    if len(upper) >= 5:
        names.append(f"{upper[:3]}_{upper[3:]}")
        names.append(f"{upper[:3]}-{upper[3:]}")
        names.append(f"{lower[:3]}_{lower[3:]}")
        names.append(f"{lower[:3]}-{lower[3:]}")

    # Add mixed digit names
    if len(digits) >= 5:
        names.append(f"{upper[:3]}{digits[3:]}")
        names.append(f"{lower[:3]}{digits[3:]}")

    return names


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_adcli_join_with_various_names(client: Client, provider: GenericADProvider):
    """
    :title: adcli join with various computer names
    :description: Iterates through a list of complex computer names (mixed case, digits,
                  separators) and verifies adcli can join and create the account correctly.
    :expectedresults:
        1. Join succeeds for each name.
        2. Computer object exists in AD with the correct name.
        3. Keytab contains the correct principals.
    """
    test_names = generate_test_names(client.host.hostname)

    for computer_name in test_names:
        print(f"Testing join with computer name: {computer_name}")

        # 1. Join
        join_result = client.adcli.join(
            domain=provider.host.domain,
            login_user=provider.host.adminuser,
            password=provider.host.adminpw,
            args=["--verbose", f"--computer-name={computer_name}"],
            krb=False
        )
        assert join_result.rc == 0, f"Join failed for name '{computer_name}': {join_result.stderr}"

        # 2. Verify in AD via adcli show-computer
        # This confirms the computer object was created successfully
        show_result = client.adcli.show_computer(
            domain=provider.host.domain,
            login_user=provider.host.adminuser,
            password=provider.host.adminpw,
            args=[f"--computer-name={computer_name}"],
            krb=False
        )
        assert show_result.rc == 0, f"Computer object '{computer_name}' not found via show-computer. stderr: {show_result.stderr}"

        # 3. Verify Keytab
        klist = client.host.conn.exec(["klist", "-k"])
        assert klist.rc == 0

        # Keytab should contain the computer name (upper or as provided depending on AD behavior)
        # AD usually uppercases the SAMAccountName, but adcli might store it as requested.
        # We check for the name in the keytab output.
        assert computer_name.upper() in klist.stdout or computer_name in klist.stdout, \
            f"Computer name '{computer_name}' not found in keytab."
        delete_result = client.adcli.delete_computer(
            domain=provider.host.domain,
            login_user=provider.host.adminuser,
            password=provider.host.adminpw,
            args=[computer_name], # Pass the specific name to delete
            krb=False
        )
        assert delete_result.rc == 0, f"Delete failed for '{computer_name}': {delete_result.stderr}"

        # Verify deletion
        # Using show-computer to confirm it's gone
        show_result = client.adcli.show_computer(
            domain=provider.host.domain,
            login_user=provider.host.adminuser,
            password=provider.host.adminpw,
            args=[f"--computer-name={computer_name}"], # Explicitly ask for this computer
            krb=False
        )
        assert show_result.rc != 0, f"Computer '{computer_name}' still exists after deletion!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_adcli_delete_computer_by_name(client: Client, provider: GenericADProvider):
    """
    :title: adcli delete-computer with various names
    :description: Verifies adcli delete-computer works for various name formats.
    """
    test_names = generate_test_names(client.host.hostname)

    for computer_name in test_names:
        print(f"Testing delete for computer name: {computer_name}")

        # Setup: Join first to create the object
        client.adcli.join(
            domain=provider.host.domain,
            login_user=provider.host.adminuser,
            password=provider.host.adminpw,
            args=[f"--computer-name={computer_name}"],
            krb=False
        )

        # Test: Delete the computer explicitly by name
        delete_result = client.adcli.delete_computer(
            domain=provider.host.domain,
            login_user=provider.host.adminuser,
            password=provider.host.adminpw,
            args=[computer_name], # Pass the specific name to delete
            krb=False
        )
        assert delete_result.rc == 0, f"Delete failed for '{computer_name}': {delete_result.stderr}"

        # Verify deletion
        # Using show-computer to confirm it's gone
        show_result = client.adcli.show_computer(
            domain=provider.host.domain,
            login_user=provider.host.adminuser,
            password=provider.host.adminpw,
            args=[f"--computer-name={computer_name}"], # Explicitly ask for this computer
            krb=False
        )
        assert show_result.rc != 0, f"Computer '{computer_name}' still exists after deletion!"


#@pytest.mark.importance("medium")
#@pytest.mark.topology(KnownTopologyGroup.AnyAD)
#def test_adcli_join_long_name_fail(client: Client, provider: GenericADProvider):
#    """
#    :title: adcli join with name > 15 chars (NetBIOS limit)
#    :description: Verifies that joining with a computer name longer than the NetBIOS limit (15 chars)
#                  fails or handles the error as expected.
#    """
#    # NetBIOS limit is 15. The bash script tested for > 19, so let's try 20 chars.
#    long_name = "THISNAMEISTOOLONG123"
#
#    join_result = client.adcli.join(
#        domain=provider.host.domain,
#        login_user=provider.host.adminuser,
#        password=provider.host.adminpw,
#        args=["--verbose", f"--computer-name={long_name}"],
#        krb=False
#    )
#
#    # Expecting failure or a specific warning.
#    # The bash script expected failure with "Couldn't create computer account"
#    if join_result.rc != 0:
#        assert "Couldn't create computer account" in join_result.stderr or "toolong" in join_result.stderr.lower()
#    else:
#        # If it succeeds, it might have truncated the name. We should warn or check.
#        # For this test, we follow the bash script's expectation of failure.
#        pytest.fail(f"Join unexpectedly succeeded with long name '{long_name}'")
