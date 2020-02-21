from setuptools import setup, find_packages

setup(
    name='dvcli-k8s',
    version='0.0.1',
    py_modules=find_packages(),
    install_requires=[
        'Click==7.0',
        'pykeepass==3.2.0',
        'Jinja2==2.11.1'
    ],
    entry_points='''
        [dvcli.plugins]
        k8s=k8s.cli:k8s
    ''',
)
