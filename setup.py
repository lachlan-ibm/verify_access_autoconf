from setuptools import find_packages, setup
import os

setup(
    name='isva_configurator',
    version='0.1.%s' % os.environ.get('TRAVIS_BUILD_NUMBER', 0),
    description='YAML based configuration automation for IBM Security Verify Access',
    author='Lachlan Gleeson',
    author_email='lgleeson@au1.ibm.com',
    license='MIT',
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=[
        'requests>=2.23.0'
        'PyYAML>=5.3',
        'pyisam',
        'kubernetes>=10.0.1',
        'docker-compose>=1.25.4'
    ],
    url='https://github.ibm.com/lgleeson/ISVAConfigurationAutomation',
    zip_safe=False
)
