#
# Copyright (C) 2016 FreeIPA Contributors see COPYING for license
#

"""
temporary module for host enrollment
"""
import getpass
import os
import sys
import tempfile

import gssapi
from six.moves.urllib.parse import urlparse, urlunparse

import ipaclient
from ipalib.constants import CACERT
from ipalib import certstore, errors, x509
from ipaplatform.paths import paths
from ipapython.ipa_log_manager import root_logger
from ipapython.dn import DN
from ipapython import ipaldap
from ipapython import ipautil
from ipapython.ipautil import (
    run, user_input, CalledProcessError)
from ipapython import kernel_keyring
from ipapython import sysrestore


SUCCESS = 0
CLIENT_INSTALL_ERROR = 1
CLIENT_NOT_CONFIGURED = 2
CLIENT_ALREADY_CONFIGURED = 3
CLIENT_UNINSTALL_ERROR = 4 # error after restoring files/state

fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
statestore = sysrestore.StateFile(paths.IPA_CLIENT_SYSRESTORE)

CCACHE_FILE = paths.IPA_DNS_CCACHE


def cert_summary(msg, certs, indent='    '):
    if msg:
        s = '%s\n' % msg
    else:
        s = ''
    for cert in certs:
        s += '%sSubject:     %s\n' % (indent, cert.subject)
        s += '%sIssuer:      %s\n' % (indent, cert.issuer)
        s += '%sValid From:  %s\n' % (indent, cert.valid_not_before_str)
        s += '%sValid Until: %s\n' % (indent, cert.valid_not_after_str)
        s += '\n'
    s = s[:-1]

    return s


def get_certs_from_ldap(server, base_dn, realm, ca_enabled):
    conn = ipaldap.IPAdmin(server, sasl_nocanon=True)
    try:
        conn.do_sasl_gssapi_bind()
        certs = certstore.get_ca_certs(conn, base_dn, realm, ca_enabled)
    except errors.NotFound:
        raise errors.NoCertificateError(entry=server)
    except errors.NetworkError as e:
        raise errors.NetworkError(uri=conn.ldap_uri, error=str(e))
    except Exception as e:
        raise errors.LDAPError(str(e))
    finally:
        conn.unbind()

    return certs


def get_ca_certs_from_file(url):
    '''
    Get the CA cert from a user supplied file and write it into the
    CACERT file.

    Raises errors.NoCertificateError if unable to read cert.
    Raises errors.FileError if unable to write cert.
    '''

    try:
        parsed = urlparse(url, 'file')
    except Exception:
        raise errors.FileError(reason="unable to parse file url '%s'" % url)

    if parsed.scheme != 'file':
        raise errors.FileError(reason="url is not a file scheme '%s'" % url)

    filename = parsed.path

    if not os.path.exists(filename):
        raise errors.FileError(reason="file '%s' does not exist" % filename)

    if not os.path.isfile(filename):
        raise errors.FileError(reason="file '%s' is not a file" % filename)

    root_logger.debug("trying to retrieve CA cert from file %s", filename)
    try:
        certs = x509.load_certificate_list_from_file(filename)
    except Exception:
        raise errors.NoCertificateError(entry=filename)

    return certs


def get_ca_certs_from_http(url, warn=True):
    '''
    Use HTTP to retrieve the CA cert and write it into the CACERT file.
    This is insecure and should be avoided.

    Raises errors.NoCertificateError if unable to retrieve and write cert.
    '''

    if warn:
        root_logger.warning("Downloading the CA certificate via HTTP, " +
                            "this is INSECURE")

    root_logger.debug("trying to retrieve CA cert via HTTP from %s", url)
    try:

        result = run([paths.BIN_CURL, "-o", "-", url], capture_output=True)
    except CalledProcessError:
        raise errors.NoCertificateError(entry=url)
    stdout = result.output

    try:
        certs = x509.load_certificate_list(stdout)
    except Exception:
        raise errors.NoCertificateError(entry=url)

    return certs


def get_ca_certs_from_ldap(server, basedn, realm):
    '''
    Retrieve th CA cert from the LDAP server by binding to the
    server with GSSAPI using the current Kerberos credentials.
    Write the retrieved cert into the CACERT file.

    Raises errors.NoCertificateError if cert is not found.
    Raises errors.NetworkError if LDAP connection can't be established.
    Raises errors.LDAPError for any other generic LDAP error.
    Raises errors.OnlyOneValueAllowed if more than one cert is found.
    Raises errors.FileError if unable to write cert.
    '''

    root_logger.debug("trying to retrieve CA cert via LDAP from %s", server)

    try:
        certs = get_certs_from_ldap(server, basedn, realm, False)
    except Exception as e:
        root_logger.debug("get_ca_certs_from_ldap() error: %s", e)
        raise

    certs = [x509.load_certificate(c[0], x509.DER) for c in certs
             if c[2] is not False]

    return certs


def validate_new_ca_certs(existing_ca_certs, new_ca_certs, ask,
                          override=False):
    if existing_ca_certs is None:
        root_logger.info(
            cert_summary("Successfully retrieved CA cert", new_ca_certs))
        return

    existing_ca_certs = set(existing_ca_certs)
    new_ca_certs = set(new_ca_certs)
    if existing_ca_certs > new_ca_certs:
        root_logger.warning(
            "The CA cert available from the IPA server does not match the\n"
            "local certificate available at %s" % CACERT)
        root_logger.warning(
            cert_summary("Existing CA cert:", existing_ca_certs))
        root_logger.warning(
            cert_summary("Retrieved CA cert:", new_ca_certs))
        if override:
            root_logger.warning("Overriding existing CA cert\n")
        elif not ask or not user_input(
                "Do you want to replace the local certificate with the CA\n"
                "certificate retrieved from the IPA server?", True):
            raise errors.CertificateInvalidError(name='Retrieved CA')
    else:
        root_logger.debug(
                "Existing CA cert and Retrieved CA cert are identical")


def print_port_conf_info():
    root_logger.info(
        "Please make sure the following ports are opened "
        "in the firewall settings:\n"
        "     TCP: 80, 88, 389\n"
        "     UDP: 88 (at least one of TCP/UDP ports 88 has to be open)\n"
        "Also note that following ports are necessary for ipa-client "
        "working properly after enrollment:\n"
        "     TCP: 464\n"
        "     UDP: 464, 123 (if NTP enabled)")


def configure_krb5_conf(cli_realm, cli_domain, cli_server, cli_kdc, dnsok,
        options, filename, client_domain, client_hostname):

    krbconf = ipaclient.ipachangeconf.IPAChangeConf("IPA Installer")
    krbconf.setOptionAssignment((" = ", " "))
    krbconf.setSectionNameDelimiters(("[","]"))
    krbconf.setSubSectionDelimiters(("{","}"))
    krbconf.setIndent(("","  ","    "))

    opts = [{'name':'comment', 'type':'comment', 'value':'File modified by ipa-client-install'},
            {'name':'empty', 'type':'empty'},
            {'name':'includedir', 'type':'option', 'value':paths.COMMON_KRB5_CONF_DIR, 'delim':' '}]

    # SSSD include dir
    if options.sssd:
        opts.append({'name':'includedir', 'type':'option', 'value':paths.SSSD_PUBCONF_KRB5_INCLUDE_D_DIR, 'delim':' '})
        opts.append({'name':'empty', 'type':'empty'})

    #[libdefaults]
    libopts = [{'name':'default_realm', 'type':'option', 'value':cli_realm}]
    if not dnsok or not cli_kdc or options.force:
        libopts.append({'name':'dns_lookup_realm', 'type':'option', 'value':'false'})
        libopts.append({'name':'dns_lookup_kdc', 'type':'option', 'value':'false'})
    else:
        libopts.append({'name':'dns_lookup_realm', 'type':'option', 'value':'true'})
        libopts.append({'name':'dns_lookup_kdc', 'type':'option', 'value':'true'})
    libopts.append({'name':'rdns', 'type':'option', 'value':'false'})
    libopts.append({'name':'ticket_lifetime', 'type':'option', 'value':'24h'})
    libopts.append({'name':'forwardable', 'type':'option', 'value':'true'})
    libopts.append({'name':'udp_preference_limit', 'type':'option', 'value':'0'})

    # Configure KEYRING CCACHE if supported
    if kernel_keyring.is_persistent_keyring_supported():
        root_logger.debug("Enabling persistent keyring CCACHE")
        libopts.append({'name':'default_ccache_name', 'type':'option',
            'value':'KEYRING:persistent:%{uid}'})

    opts.append({'name':'libdefaults', 'type':'section', 'value':libopts})
    opts.append({'name':'empty', 'type':'empty'})

    #the following are necessary only if DNS discovery does not work
    kropts = []
    if not dnsok or not cli_kdc or options.force:
        #[realms]
        for server in cli_server:
            kropts.append({'name':'kdc', 'type':'option', 'value':ipautil.format_netloc(server, 88)})
            kropts.append({'name':'master_kdc', 'type':'option', 'value':ipautil.format_netloc(server, 88)})
            kropts.append({'name':'admin_server', 'type':'option', 'value':ipautil.format_netloc(server, 749)})
            kropts.append({'name': 'kpasswd_server',
                           'type': 'option',
                           'value': ipautil.format_netloc(server, 464)
                          })
        kropts.append({'name':'default_domain', 'type':'option', 'value':cli_domain})
    kropts.append({'name':'pkinit_anchors', 'type':'option', 'value':'FILE:%s' % CACERT})
    ropts = [{'name':cli_realm, 'type':'subsection', 'value':kropts}]

    opts.append({'name':'realms', 'type':'section', 'value':ropts})
    opts.append({'name':'empty', 'type':'empty'})

    #[domain_realm]
    dropts = [{'name':'.'+cli_domain, 'type':'option', 'value':cli_realm},
              {'name':cli_domain, 'type':'option', 'value':cli_realm},
              {'name':client_hostname, 'type':'option', 'value':cli_realm}]

    #add client domain mapping if different from server domain
    if cli_domain != client_domain:
        dropts.append({'name':'.'+client_domain, 'type':'option', 'value':cli_realm})
        dropts.append({'name':client_domain, 'type':'option', 'value':cli_realm})

    opts.append({'name':'domain_realm', 'type':'section', 'value':dropts})
    opts.append({'name':'empty', 'type':'empty'})

    root_logger.debug("Writing Kerberos configuration to %s:", filename)
    root_logger.debug("%s", krbconf.dump(opts))

    krbconf.newConf(filename, opts)
    os.chmod(filename, 0o644)

    return 0


def get_ca_certs(fstore, options, server, basedn, realm):
    '''
    Examine the different options and determine a method for obtaining
    the CA cert.

    If successful the CA cert will have been written into CACERT.

    Raises errors.NoCertificateError if not successful.

    The logic for determining how to load the CA cert is as follow:

    In the OTP case (not -p and -w):

    1. load from user supplied cert file
    2. else load from HTTP

    In the 'user_auth' case ((-p and -w) or interactive):

    1. load from user supplied cert file
    2. load from LDAP using SASL/GSS/Krb5 auth
       (provides mutual authentication, integrity and security)
    3. if LDAP failed and interactive ask for permission to
       use insecure HTTP (default: No)

    In the unattended case:

    1. load from user supplied cert file
    2. load from HTTP if --force specified else fail

    In all cases if HTTP is used emit warning message
    '''

    ca_file = CACERT + ".new"

    def ldap_url():
        return urlunparse(('ldap', ipautil.format_netloc(server),
                           '', '', '', ''))

    def file_url():
        return urlunparse(('file', '', options.ca_cert_file,
                           '', '', ''))

    def http_url():
        return urlunparse(('http', ipautil.format_netloc(server),
                           '/ipa/config/ca.crt', '', '', ''))


    interactive = not options.unattended
    otp_auth = options.principal is None and options.password is not None
    existing_ca_certs = None
    ca_certs = None

    if options.ca_cert_file:
        url = file_url()
        try:
            ca_certs = get_ca_certs_from_file(url)
        except errors.FileError as e:
            root_logger.debug(e)
            raise
        except Exception as e:
            root_logger.debug(e)
            raise errors.NoCertificateError(entry=url)
        root_logger.debug("CA cert provided by user, use it!")
    else:
        if os.path.exists(CACERT):
            if os.path.isfile(CACERT):
                try:
                    existing_ca_certs = x509.load_certificate_list_from_file(
                        CACERT)
                except Exception as e:
                    raise errors.FileError(reason=u"Unable to load existing" +
                                           " CA cert '%s': %s" % (CACERT, e))
            else:
                raise errors.FileError(reason=u"Existing ca cert '%s' is " +
                                       "not a plain file" % (CACERT))

        if otp_auth:
            if existing_ca_certs:
                root_logger.info("OTP case, CA cert preexisted, use it")
            else:
                url = http_url()
                override = not interactive
                if interactive and not user_input(
                    "Do you want to download the CA cert from " + url + " ?\n"
                    "(this is INSECURE)", False):
                    raise errors.NoCertificateError(message=u"HTTP certificate"
                            " download declined by user")
                try:
                    ca_certs = get_ca_certs_from_http(url, override)
                except Exception as e:
                    root_logger.debug(e)
                    raise errors.NoCertificateError(entry=url)

                validate_new_ca_certs(existing_ca_certs, ca_certs, False,
                                      override)
        else:
            # Auth with user credentials
            try:
                url = ldap_url()
                ca_certs = get_ca_certs_from_ldap(server, basedn, realm)
                validate_new_ca_certs(existing_ca_certs, ca_certs, interactive)
            except errors.FileError as e:
                root_logger.debug(e)
                raise
            except (errors.NoCertificateError, errors.LDAPError) as e:
                root_logger.debug(str(e))
                url = http_url()
                if existing_ca_certs:
                    root_logger.warning(
                        "Unable to download CA cert from LDAP\n"
                        "but found preexisting cert, using it.\n")
                elif interactive and not user_input(
                    "Unable to download CA cert from LDAP.\n"
                    "Do you want to download the CA cert from " + url + "?\n"
                    "(this is INSECURE)", False):
                    raise errors.NoCertificateError(message=u"HTTP "
                                "certificate download declined by user")
                elif not interactive and not options.force:
                    root_logger.error(
                        "In unattended mode without a One Time Password "
                        "(OTP) or without --ca-cert-file\nYou must specify"
                        " --force to retrieve the CA cert using HTTP")
                    raise errors.NoCertificateError(message=u"HTTP "
                                "certificate download requires --force")
                else:
                    try:
                        ca_certs = get_ca_certs_from_http(url)
                    except Exception as e:
                        root_logger.debug(e)
                        raise errors.NoCertificateError(entry=url)
                    validate_new_ca_certs(existing_ca_certs, ca_certs,
                                          interactive)
            except Exception as e:
                root_logger.debug(str(e))
                raise errors.NoCertificateError(entry=url)

        if ca_certs is None and existing_ca_certs is None:
            raise errors.InternalError(u"expected CA cert file '%s' to "
                                       u"exist, but it's absent" % (ca_file))

    if ca_certs is not None:
        try:
            ca_certs = [cert.der_data for cert in ca_certs]
            x509.write_certificate_list(ca_certs, ca_file)
        except Exception as e:
            if os.path.exists(ca_file):
                try:
                    os.unlink(ca_file)
                except OSError as e:
                    root_logger.error(
                        "Failed to remove '%s': %s", ca_file, e)
            raise errors.FileError(reason =
                u"cannot write certificate file '%s': %s" % (ca_file, e))

        os.rename(ca_file, CACERT)

    # Make sure the file permissions are correct
    try:
        os.chmod(CACERT, 0o644)
    except Exception as e:
        raise errors.FileError(reason=u"Unable set permissions on ca "
                               u"cert '%s': %s" % (CACERT, e))


def enroll(hostname, cli_realm, cli_domain, cli_server, cli_kdc, client_domain,
           cli_basedn, dnsok, options, env):
    host_principal = 'host/%s@%s' % (hostname, cli_realm)

    nolog = tuple()
    # First test out the kerberos configuration
    try:
        (krb_fd, krb_name) = tempfile.mkstemp()
        os.close(krb_fd)
        if configure_krb5_conf(
                cli_realm=cli_realm,
                cli_domain=cli_domain,
                cli_server=cli_server,
                cli_kdc=cli_kdc,
                dnsok=False,
                options=options,
                filename=krb_name,
                client_domain=client_domain,
                client_hostname=hostname):
            root_logger.error("Test kerberos configuration failed")
            return CLIENT_INSTALL_ERROR
        env['KRB5_CONFIG'] = krb_name
        ccache_dir = tempfile.mkdtemp(prefix='krbcc')
        ccache_name = os.path.join(ccache_dir, 'ccache')
        join_args = [paths.SBIN_IPA_JOIN,
                     "-s", cli_server[0],
                     "-b", str(ipautil.realm_to_suffix(cli_realm)),
                     "-h", hostname]
        if options.debug:
            join_args.append("-d")
            env['XMLRPC_TRACE_CURL'] = 'yes'
        if options.force_join:
            join_args.append("-f")
        if options.principal is not None:
            stdin = None
            principal = options.principal
            if principal.find('@') == -1:
                principal = '%s@%s' % (principal, cli_realm)
            if options.password is not None:
                stdin = options.password
            else:
                if not options.unattended:
                    try:
                        stdin = getpass.getpass("Password for %s: " % principal)
                    except EOFError:
                        stdin = None
                    if not stdin:
                        root_logger.error(
                            "Password must be provided for %s.", principal)
                        return CLIENT_INSTALL_ERROR
                else:
                    if sys.stdin.isatty():
                        root_logger.error("Password must be provided in " +
                            "non-interactive mode.")
                        root_logger.info("This can be done via " +
                            "echo password | ipa-client-install ... " +
                            "or with the -w option.")
                        return CLIENT_INSTALL_ERROR
                    else:
                        stdin = sys.stdin.readline()

            try:
                ipautil.kinit_password(principal, stdin, ccache_name,
                                       config=krb_name)
            except RuntimeError as e:
                print_port_conf_info()
                root_logger.error("Kerberos authentication failed: %s" % e)
                return CLIENT_INSTALL_ERROR
        elif options.keytab:
            join_args.append("-f")
            if os.path.exists(options.keytab):
                try:
                    ipautil.kinit_keytab(host_principal, options.keytab,
                                         ccache_name,
                                         config=krb_name,
                                         attempts=options.kinit_attempts)
                except gssapi.exceptions.GSSError as e:
                    print_port_conf_info()
                    root_logger.error("Kerberos authentication failed: %s"
                                      % e)
                    return CLIENT_INSTALL_ERROR
            else:
                root_logger.error("Keytab file could not be found: %s"
                                  % options.keytab)
                return CLIENT_INSTALL_ERROR
        elif options.password:
            nolog = (options.password,)
            join_args.append("-w")
            join_args.append(options.password)
        elif options.prompt_password:
            if options.unattended:
                root_logger.error(
                    "Password must be provided in non-interactive mode")
                return CLIENT_INSTALL_ERROR
            try:
                password = getpass.getpass("Password: ")
            except EOFError:
                password = None
            if not password:
                root_logger.error("Password must be provided.")
                return CLIENT_INSTALL_ERROR
            join_args.append("-w")
            join_args.append(password)
            nolog = (password,)

        env['KRB5CCNAME'] = os.environ['KRB5CCNAME'] = ccache_name
        # Get the CA certificate
        try:
            os.environ['KRB5_CONFIG'] = env['KRB5_CONFIG']
            get_ca_certs(fstore, options, cli_server[0], cli_basedn,
                         cli_realm)
            del os.environ['KRB5_CONFIG']
        except errors.FileError as e:
            root_logger.error(e)
            return CLIENT_INSTALL_ERROR
        except Exception as e:
            root_logger.error("Cannot obtain CA certificate\n%s", e)
            return CLIENT_INSTALL_ERROR

        # Now join the domain
        result = run(
            join_args, raiseonerr=False, env=env, nolog=nolog,
            capture_error=True)
        stderr = result.error_output

        if result.returncode != 0:
            root_logger.error("Joining realm failed: %s", stderr)
            if not options.force:
                if result.returncode == 13:
                    root_logger.info("Use --force-join option to override "
                                     "the host entry on the server "
                                     "and force client enrollment.")
                return CLIENT_INSTALL_ERROR
            root_logger.info("Use ipa-getkeytab to obtain a host " +
                "principal for this server.")
        else:
            root_logger.info("Enrolled in IPA realm %s", cli_realm)

        start = stderr.find('Certificate subject base is: ')
        if start >= 0:
            start = start + 29
            subject_base = stderr[start:]
            subject_base = subject_base.strip()
            subject_base = DN(subject_base)

        if options.principal is not None:
            run(["kdestroy"], raiseonerr=False, env=env)

        # Obtain the TGT. We do it with the temporary krb5.conf, so that
        # only the KDC we're installing under is contacted.
        # Other KDCs might not have replicated the principal yet.
        # Once we have the TGT, it's usable on any server.
        try:
            ipautil.kinit_keytab(host_principal, paths.KRB5_KEYTAB,
                                 CCACHE_FILE,
                                 config=krb_name,
                                 attempts=options.kinit_attempts)
            env['KRB5CCNAME'] = os.environ['KRB5CCNAME'] = CCACHE_FILE
        except gssapi.exceptions.GSSError as e:
            print_port_conf_info()
            root_logger.error("Failed to obtain host TGT: %s" % e)
            # failure to get ticket makes it impossible to login and bind
            # from sssd to LDAP, abort installation and rollback changes
            return CLIENT_INSTALL_ERROR

    finally:
        try:
            os.remove(krb_name)
        except OSError:
            root_logger.error("Could not remove %s", krb_name)
        try:
            os.rmdir(ccache_dir)
        except OSError:
            pass
        try:
            os.remove(krb_name + ".ipabkp")
        except OSError:
            root_logger.error("Could not remove %s.ipabkp", krb_name)

    # DO NOT backup krb5.conf for now
    # fstore.backup_file(paths.KRB5_CONF)
    if configure_krb5_conf(
            cli_realm=cli_realm,
            cli_domain=cli_domain,
            cli_server=cli_server,
            cli_kdc=cli_kdc,
            dnsok=dnsok,
            options=options,
            filename=paths.KRB5_CONF,
            client_domain=client_domain,
            client_hostname=hostname):
        return CLIENT_INSTALL_ERROR

    root_logger.info(
        "Configured /etc/krb5.conf for IPA realm %s", cli_realm)
