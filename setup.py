from distutils.core import setup
from glob import glob

setup(name='autosecure',
    version='0.1.0',
    zip_safe=False,
    packages = ['autosecure', 'autosecure.handlers'],
    include_package_data=True,
    install_requires=[
        "pynids",
        "requests",
        "pyquery",
    ],
    entry_points = {
        'console_scripts': [
            'autosecure = autosecure.main:main',
        ],
    }
) 
