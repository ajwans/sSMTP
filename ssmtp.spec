#%define configopt --enable-ssl --enable-md5auth
%define configopt --enable-ssl

Summary: Extremely simple MTA to get mail off the system to a Mailhub.
Name: ssmtp
Version: 2.60
Release: 8
License: GPL
Group: System/Servers
URL: http://packages.debian.org/stable/mail/ssmtp.html
BuildRoot: %{_tmppath}/root-%{name}-%{version}
Source: ftp://ftp.debian.org/debian/pool/main/s/%{name}/%{name}_%{version}.%{release}.tar.gz
Patch: %{name}_%{version}.%{release}.patch

%description
A secure, effective and simple way of getting mail off a system to your mail
hub. It contains no suid-binaries or other dangerous things - no mail spool
to poke around in, and no daemons running in the background. Mail is simply
forwarded to the configured mailhost. Extremely easy configuration.

WARNING: the above is all it does; it does not receive mail, expand aliases
or manage a queue. That belongs on a mail hub with a system administrator.

%prep
%setup
export PATCH_GET=0
%patch -p1

%build
%configure %{configopt}
%{__make}

%install
%{__rm} -rf %{buildroot}
%{__make} INSTALL_PREFIX="%{buildroot}" install

%post
%{_sbindir}/ssmtp_generate_config %{_sysconfdir}/ssmtp/ssmtp.conf

%postun

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-,root,root)
%doc COPYING INSTALL README TLS
%config(noreplace) %{_sysconfdir}/ssmtp/*
%{_sbindir}/*
%{_mandir}/man?/*
