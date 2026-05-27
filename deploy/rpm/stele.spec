# stele.spec — RPM packaging for Red Hat / Fedora / SUSE / Amazon Linux.
#
# Build with:
#   ARCH=x86_64 VERSION=0.1.0 ./deploy/rpm/build-rpm.sh
#   ARCH=aarch64 VERSION=0.1.0 ./deploy/rpm/build-rpm.sh
#
# This spec EXPECTS pre-built binaries under %_sourcedir/ — the release
# workflow's Go cross-compile output. We don't build Go inside rpmbuild;
# the existing reproducible build is the source of truth.

Name:           stele
Version:        %{?_stele_version:%{_stele_version}}%{!?_stele_version:0.0.0-dev}
Release:        1%{?dist}
Summary:        Provenance-anchored audit log
License:        ASL 2.0
URL:            https://github.com/desledishant10/stele
BuildArch:      %{_stele_arch}

%{?systemd_requires}
BuildRequires:  systemd-rpm-macros
Requires(pre):  shadow-utils

%description
stele is a tamper-evident append-only audit log. Producers sign
their entries; the operator chains them into an RFC 6962 Merkle tree;
witnesses cosign each checkpoint independently; external anchors
(Sigstore Rekor, drand beacon) bind everything to public ground
truth.

This package installs the operator, witness, mirror, cosigner, CLI,
backup, export-chain, watcher, and loadgen binaries plus hardened
systemd unit files and example configuration.

See /usr/share/doc/stele/PLAYBOOK.md for the operator manual.

%prep
# No source unpacking — binaries are pre-built by the release
# workflow and placed in %_sourcedir before invoking rpmbuild.

%install
rm -rf %{buildroot}

# Binaries.
install -d -m 0755 %{buildroot}%{_bindir}
for cmd in steled stele stele-witness stele-mirror stele-cosigner \
           stele-backup stele-export-chain stele-watcher stele-loadgen; do
    install -m 0755 %{_sourcedir}/${cmd} %{buildroot}%{_bindir}/${cmd}
done

# systemd units.
install -d -m 0755 %{buildroot}%{_unitdir}
install -m 0644 %{_sourcedir}/steled.service        %{buildroot}%{_unitdir}/steled.service
install -m 0644 %{_sourcedir}/stele-witness.service %{buildroot}%{_unitdir}/stele-witness.service
install -m 0644 %{_sourcedir}/stele-mirror.service  %{buildroot}%{_unitdir}/stele-mirror.service

# Example env files.
install -d -m 0750 %{buildroot}%{_sysconfdir}/stele
install -m 0640 %{_sourcedir}/steled.env.example   %{buildroot}%{_sysconfdir}/stele/steled.env.example
install -m 0640 %{_sourcedir}/witness.env.example  %{buildroot}%{_sysconfdir}/stele/witness.env.example
install -m 0640 %{_sourcedir}/mirror.env.example   %{buildroot}%{_sysconfdir}/stele/mirror.env.example

# Data dir (created empty; chowned in %pre).
install -d -m 0750 %{buildroot}%{_sharedstatedir}/stele

# Documentation.
install -d -m 0755 %{buildroot}%{_docdir}/stele
install -m 0644 %{_sourcedir}/README.md      %{buildroot}%{_docdir}/stele/
install -m 0644 %{_sourcedir}/PLAYBOOK.md    %{buildroot}%{_docdir}/stele/
install -m 0644 %{_sourcedir}/RECOVERY.md    %{buildroot}%{_docdir}/stele/
install -m 0644 %{_sourcedir}/THREATMODEL.md %{buildroot}%{_docdir}/stele/
install -m 0644 %{_sourcedir}/LICENSE        %{buildroot}%{_docdir}/stele/LICENSE

%pre
# Create the `stele` system user/group before files land so the
# pre-owned directories below get the right uid/gid.
getent group stele >/dev/null || groupadd --system stele
getent passwd stele >/dev/null || useradd --system \
    --no-create-home --shell /sbin/nologin \
    --home-dir %{_sharedstatedir}/stele --gid stele stele
exit 0

%post
%systemd_post steled.service stele-witness.service stele-mirror.service
echo
echo "stele installed. Next steps:"
echo "  1. Copy %{_sysconfdir}/stele/*.env.example to *.env and edit."
echo "  2. systemctl enable --now steled    (and/or stele-witness, stele-mirror)"
echo
echo "See %{_docdir}/stele/PLAYBOOK.md for full operator guidance."

%preun
%systemd_preun steled.service stele-witness.service stele-mirror.service

%postun
%systemd_postun_with_restart steled.service stele-witness.service stele-mirror.service

%files
%license %{_docdir}/stele/LICENSE
%doc %{_docdir}/stele/README.md
%doc %{_docdir}/stele/PLAYBOOK.md
%doc %{_docdir}/stele/RECOVERY.md
%doc %{_docdir}/stele/THREATMODEL.md
%{_bindir}/steled
%{_bindir}/stele
%{_bindir}/stele-witness
%{_bindir}/stele-mirror
%{_bindir}/stele-cosigner
%{_bindir}/stele-backup
%{_bindir}/stele-export-chain
%{_bindir}/stele-watcher
%{_bindir}/stele-loadgen
%{_unitdir}/steled.service
%{_unitdir}/stele-witness.service
%{_unitdir}/stele-mirror.service
%dir %attr(0750, root, stele) %{_sysconfdir}/stele
%config(noreplace) %attr(0640, root, stele) %{_sysconfdir}/stele/steled.env.example
%config(noreplace) %attr(0640, root, stele) %{_sysconfdir}/stele/witness.env.example
%config(noreplace) %attr(0640, root, stele) %{_sysconfdir}/stele/mirror.env.example
%dir %attr(0750, stele, stele) %{_sharedstatedir}/stele

%changelog
* %{?_stele_changelog_date:%(date '+%a %b %d %Y')} stele maintainers <https://github.com/desledishant10/stele>
- See CHANGELOG.md in /usr/share/doc/stele/
