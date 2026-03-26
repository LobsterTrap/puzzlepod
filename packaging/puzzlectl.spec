%global project_name   puzzlepod

%if 0%{?commit:1}
%global source_name    %{project_name}-%{commit}
%global rpm_release    0.%{commitdate}.git%{shortcommit}%{?dist}
%else
%global source_name    %{project_name}-%{version}
%global rpm_release    1%{?dist}
%endif

Name:           puzzlectl
Version:        0.1.0
Release:        %{rpm_release}
Summary:        PuzzlePod command-line management tool
License:        Apache-2.0
URL:            https://github.com/LobsterTrap/PuzzlePod
Source0:        %{source_name}.tar.gz

ExclusiveArch:  x86_64 aarch64

BuildRequires:  rust-packaging
BuildRequires:  cargo >= 1.75
BuildRequires:  dbus-devel

Requires:       dbus
Requires:       puzzled = %{version}-%{release}

%description
puzzlectl is the command-line interface for managing PuzzlePod agent
sandboxes, branches, profiles, policies, and audit events. It communicates
with the puzzled governance daemon via D-Bus.

Key commands include branch management (create, list, inspect, approve,
reject, rollback, diff), agent lifecycle (list, info, kill), profile
management (list, show, validate, test), policy management (reload, test),
and audit queries (list, export, verify).

Includes an interactive terminal UI (puzzlectl tui) with a multi-pane
dashboard, real-time D-Bus signal updates, governance review workflows,
credential management, and audit log viewer.

%prep
%autosetup -n %{source_name}

%build
cargo build --release --bin puzzlectl

%install
install -D -m 0755 target/release/puzzlectl %{buildroot}%{_bindir}/puzzlectl
install -D -m 0644 man/puzzlectl.1 %{buildroot}%{_mandir}/man1/puzzlectl.1

%files
%license LICENSE
%doc README.md
%{_bindir}/puzzlectl
%{_mandir}/man1/puzzlectl.1*

%changelog
* Mon Mar 09 2026 Francis Chow <fchow@redhat.com> - 0.1.0-1
- Add git snapshot macros for COPR pre-release builds
- Add ExclusiveArch

* Sat Mar 07 2026 Francis Chow <fchow@redhat.com> - 0.1.0-0
- Initial package
