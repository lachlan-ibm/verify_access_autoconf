import os
from setuptools import setup, find_packages, Command

class CleanCommand(Command):
    """Custom clean command to tidy up the project root."""
    user_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        for root, dirs, files in os.walk("./", topdown=False):
            for name in files:
                if name.endswith((".pyc", ".tgz", ".whl")):
                    print("remove {}".format(os.path.join(root, name)))
                    os.remove(os.path.join(root, name))
            for name in dirs:
                if name.endswith((".egg-info", "build", "dist", "__pycache__")):
                    print("remove {}".format(os.path.join(root, name)))
                    #os.rmdir(os.path.join(root, name))
                    os.system('rm -vrf {}'.format(os.path.join(root, name)))

setup(
    name='verify-access-configurator',
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
    zip_safe=False,
    cmdclass={
        'clean': CleanCommand,
    }
)
