import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "ansible/roles/wireguard"


class TestFirewallStartupOrder(unittest.TestCase):

    def test_firewall_service_precedes_wireguard(self):
        unit = (
            ROLE / "templates/cloudvpn-firewall.service.j2"
        ).read_text()

        self.assertIn(
            "Before=wg-quick@{{ wireguard_interface }}.service",
            unit,
        )
        self.assertNotIn(
            "Wants=wg-quick@{{ wireguard_interface }}.service",
            unit,
        )
        self.assertNotIn(
            "After=wg-quick@{{ wireguard_interface }}.service",
            unit,
        )

    def test_wireguard_requires_firewall(self):
        dropin = (
            ROLE / "templates/wg-quick-cloudvpn-firewall.conf.j2"
        ).read_text()

        self.assertIn(
            "Requires={{ wireguard_firewall_service_name }}",
            dropin,
        )
        self.assertIn(
            "After={{ wireguard_firewall_service_name }}",
            dropin,
        )

    def test_firewall_is_configured_before_wireguard_start(self):
        tasks = (ROLE / "tasks/main.yml").read_text()

        firewall_position = tasks.index(
            "- name: Configure firewall persistence"
        )
        wireguard_position = tasks.index(
            "- name: Enable and start WireGuard"
        )

        self.assertLess(firewall_position, wireguard_position)

    def test_firewall_dependency_is_installed(self):
        tasks = (ROLE / "tasks/firewall_persistence.yml").read_text()

        self.assertIn(
            "wg-quick-cloudvpn-firewall.conf.j2",
            tasks,
        )
        self.assertIn(
            "cloudvpn_wireguard_dependency_file.changed",
            tasks,
        )


    def test_firewall_requires_persistence(self):
        tasks = (ROLE / "tasks/main.yml").read_text()

        self.assertIn("Validate CloudVPN firewall lifecycle configuration", tasks)
        self.assertIn("wireguard_firewall_persist | bool", tasks)

    def test_unprotected_wireguard_requires_explicit_opt_in(self):
        defaults = (ROLE / "defaults/main.yml").read_text()
        tasks = (ROLE / "tasks/main.yml").read_text()

        self.assertIn("wireguard_allow_unprotected_wireguard: false", defaults)
        self.assertIn("wireguard_allow_unprotected_wireguard | bool", tasks)

    def test_disabled_firewall_removes_managed_systemd_integration(self):
        tasks = (ROLE / "tasks/firewall_disabled.yml").read_text()

        self.assertIn("enabled: false", tasks)
        self.assertIn("state: stopped", tasks)
        self.assertIn("state: absent", tasks)
        self.assertIn("daemon_reload: true", tasks)

    def test_disabled_firewall_does_not_flush_existing_rules(self):
        tasks = (ROLE / "tasks/firewall_disabled.yml").read_text()

        self.assertNotIn("iptables", tasks.lower())
        self.assertNotIn("flush", tasks.lower())
        self.assertNotIn("-F", tasks)
        self.assertNotIn("-X", tasks)

    def test_disabled_lifecycle_runs_before_wireguard_start(self):
        tasks = (ROLE / "tasks/main.yml").read_text()

        lifecycle_position = tasks.index(
            "- name: Remove managed firewall integration when explicitly disabled"
        )
        wireguard_position = tasks.index(
            "- name: Enable and start WireGuard"
        )

        self.assertLess(lifecycle_position, wireguard_position)


    def test_firewall_service_stops_before_unit_removal(self):
        tasks = (
            ROLE / "tasks/firewall_disabled.yml"
        ).read_text()

        stop_position = tasks.index(
            "- name: Stop and disable managed CloudVPN firewall service"
        )
        remove_position = tasks.index(
            "- name: Remove managed CloudVPN firewall systemd unit"
        )

        self.assertLess(stop_position, remove_position)
        self.assertIn("enabled: false", tasks)
        self.assertIn("state: stopped", tasks)

    def test_firewall_service_has_no_automatic_stop_cleanup(self):
        unit = (
            ROLE / "templates/cloudvpn-firewall.service.j2"
        ).read_text()

        self.assertNotIn("ExecStop=", unit)
        self.assertNotIn("ExecStopPost=", unit)



    def test_external_interface_is_discovered_from_ansible_facts(self):
        defaults = (ROLE / "defaults/main.yml").read_text()
        self.assertIn(
            'wireguard_external_interface: "{{ ansible_default_ipv4.interface }}"',
            defaults,
        )

    def test_external_interface_command_runs_after_package_installation(self):
        tasks = (ROLE / "tasks/main.yml").read_text()
        validation_position = tasks.index(
            "- name: Validate external network interface exists"
        )
        package_position = tasks.index("- name: Install WireGuard")
        self.assertLess(package_position, validation_position)
        self.assertIn("ansible_default_ipv4.interface is defined", tasks)
        self.assertIn("ip", tasks)

    def test_firewall_runtime_dependencies_are_explicit(self):
        defaults = (ROLE / "defaults/main.yml").read_text()
        for package in (
            "iptables", "iproute2", "python3", "util-linux", "procps"
        ):
            with self.subTest(package=package):
                self.assertIn(f"  - {package}", defaults)

    def test_playbook_explicitly_gathers_facts(self):
        playbook = (ROOT / "ansible/playbooks/wireguard.yml").read_text()
        self.assertIn("gather_facts: true", playbook)


    def test_firewall_script_changes_notify_restart_handler(self):
        tasks = (ROLE / "tasks/firewall_persistence.yml").read_text()

        normalizer_section = tasks.split(
            "- name: Install CloudVPN firewall rule normalizer", 1
        )[1].split("\n- name:", 1)[0]

        firewall_section = tasks.split(
            "- name: Install CloudVPN firewall script", 1
        )[1].split("\n- name:", 1)[0]

        self.assertNotIn(
            "notify: Restart CloudVPN firewall", normalizer_section
        )
        self.assertIn(
            "notify: Restart CloudVPN firewall", firewall_section
        )

    def test_firewall_restart_handler_restarts_correct_service(self):
        handlers = (ROLE / "handlers/main.yml").read_text()

        self.assertIn("- name: Restart CloudVPN firewall", handlers)
        self.assertIn(
            'name: "{{ wireguard_firewall_service_name }}"',
            handlers,
        )
        self.assertIn("state: restarted", handlers)

    def test_pending_handlers_are_flushed_before_wireguard_start(self):
        tasks = (ROLE / "tasks/main.yml").read_text()

        flush_position = tasks.index("ansible.builtin.meta: flush_handlers")
        start_position = tasks.index("- name: Enable and start WireGuard")

        self.assertLess(flush_position, start_position)

    def test_firewall_handler_precedes_wireguard_handler(self):
        handlers = (ROLE / "handlers/main.yml").read_text()

        firewall_position = handlers.index("- name: Restart CloudVPN firewall")
        wireguard_position = handlers.index("- name: Restart WireGuard")

        self.assertLess(firewall_position, wireguard_position)


if __name__ == "__main__":
    unittest.main()
