"""
(C) Copyright 2020 Forschungszentrum Jülich GmbH and others.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""

import click, getpass, logging, click_log, base64, re, gzip
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsIntegrityError
from jinja2 import Template

logger = logging.getLogger(__name__)
click_log.basic_config(logger)

@click.group()
def secrets():
    """
    Maintain secrets in your Kubernetes namespace.
    """
    pass

@secrets.command()
@click.option('-f', '--file', help='Path to file to read from.', type=click.Path(), required=True)
@click.option('-t', '--type', help='Type of file:\n kdbx = Keepass X Database file', type=click.Choice(['kdbx']), required=True)
@click.option('-p', '--password', help='File decryption password. Will read from hidden prompt. Beware of shell history!')
@click.option('-n', '--namespace', help='Namespace attribute of K8s Secret. Overrides files value.')
@click.option('-kg', '--kdbx-group', help='KeepassX: group name to lookup secrets.')
@click.option('-ks', '--kdbx-secret', help='KeepassX: lookup specific secret in group. Can be given multiple times. Nonexisting skipped silently.', multiple=True)
@click.pass_context
def load(ctx, file, type, password, namespace, kdbx_group, kdbx_secret):
    """
    Read from file, transform to K8s secrets and push to stdout.
    """

    tmpl_opaque = ctx.obj['JINJA2_ENV'].get_template("secret-opaque.yaml")
    tmpl_tls = ctx.obj['JINJA2_ENV'].get_template("secret-tls.yaml")

    # Load a KeepassX database...
    if type == 'kdbx':
        # Check parameters required for Keepass usage are present
        if (kdbx_group is None):
            raise click.BadParameter("You need to specifiy the KeepassX group when using --type=kdbx.", param=kdbx_group, param_hint='--kdbx-group')
        # Get the database password if not given via env var or option.
        if password is None:
            password = getpass.getpass(prompt="KeepassX file password: ")

        try:
            # Open the database (will raise if not successfull)
            kp = PyKeePass(file, password=password)

            # Get the specified group
            group = kp.find_groups(name=kdbx_group, first=True)
            if group is None:
                raise ValueError("KeepassX group \""+kdbx_group+"\" not found in file.")

            # Get the secret entries
            entries = []
            # -> get all if no specific secret name(s) given
            if not kdbx_secret:
                entries = group.entries
            # -> get all from specified secret name(s)
            else:
                for secret in kdbx_secret:
                    result = kp.find_entries(title=secret, group=group, first=True)
                    entries.append(result) if result is not None else []

            # Now iterate the entries...
            for entry in entries:

                title = entry.title
                props = entry.custom_properties
                ns = props.pop('namespace', None)
                # override (or enhance) with cmdline namespace
                ns = ns if namespace is None else namespace
                lbl = props.pop('labels', None)

                # Entries without attachments are K8s Secrets of type "Opaque"
                if not entry.attachments:
                    # if a password and/or username attribute is present, we need to add it
                    # manually, as it is filtered from entry.custom_properties
                    if entry.password:
                        props['password'] = entry.password
                    if entry.username:
                        props['username'] = entry.username

                    # Render opaque template
                    print(tmpl_opaque.render(title=title, namespace=ns, labels=lbl, data=props))

                # Entries with attachments are K8s Secrets of type "Tls"
                else:
                    #print(entry.attachments)
                    #print(entry.dump_xml().decode())
                    certfile = list(filter(lambda f : re.search(r"^.*[Cc][Ee][Rr][Tt].*\.pem$", f.filename), entry.attachments))
                    keyfile = list(filter(lambda f : re.search(r"^.*[Kk][Ee][Yy].*\.pem$", f.filename), entry.attachments))
                    chainfile = list(filter(lambda f : re.search(r"^.*[Cc][Hh][Aa][Ii][Nn].*\.pem$", f.filename), entry.attachments))

                    # skip this entry if we have found ambiguous filenames...
                    if len(certfile) > 1 or len(keyfile) > 1 or len(chainfile) > 1:
                        logger.warning("KeepassX group \""+kdbx_group+"\", secret \""+title+"\": ambiguous file names for TLS PEM handling. Skipping.")
                        continue

                    # skip this entry if we did not find all necessary files
                    if not certfile or  not keyfile or not chainfile:
                        logger.warning("KeepassX group \""+kdbx_group+"\", secret \""+title+"\": missing some files for TLS PEM handling. Skipping.")
                        continue

                    cert = str(base64.b64encode(certfile[0].data+b'\n'+chainfile[0].data), 'utf-8')
                    key = str(base64.b64encode(keyfile[0].data), 'utf-8')

                    # Render opaque template
                    print(tmpl_tls.render(title=title, namespace=ns, labels=lbl, cert=cert, key=key))


        except (FileNotFoundError, IsADirectoryError) as e:
            logger.error("Could not read from \"%s\"", file)
        except (CredentialsIntegrityError, ValueError) as e:
            logger.error(e)
