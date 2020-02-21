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

import click
from .secrets.cli import secrets

from jinja2 import Environment, FileSystemLoader, select_autoescape
import os
root = os.path.dirname(os.path.abspath(__file__))
templates_dir = os.path.join(root, 'templates')
env = Environment(
    loader = FileSystemLoader(templates_dir),
    autoescape=select_autoescape(['html', 'xml'])
)

@click.group()
@click.pass_context
def k8s(ctx):
    """
    Dataverse on Kubernetes related commands.
    """
    # ensure that ctx.obj exists and is a dict
    ctx.ensure_object(dict)
    # pass to everyone who needs it the template engine (load once, reuse)
    ctx.obj['JINJA2_ENV'] = env

### ADD COMMAND FROM SUBMODULES
k8s.add_command(secrets)
