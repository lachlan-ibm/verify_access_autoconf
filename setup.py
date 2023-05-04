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

#Use the README.md file as the pypi description
from pathlib import Path
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name='verify_access_autoconf',
    version='0.2.%s' % os.environ.get('TRAVIS_BUILD_NUMBER', 0),
    description='YAML based configuration automation for IBM Security Verify Access',
    author='Lachlan Gleeson',
    author_email='lgleeson@au1.ibm.com',
    license='Apache2.0',
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=['requests>=2.23.0',
                      'PyYAML>=5.3',
                      'pyisva>=0.1',
                      'kubernetes>=10.0.1',
                      'docker-compose',
                      'typing'
    ],
    url='https://github.ibm.com/lachlan-ibm/verify_access_autoconf',
    zip_safe=False,
    cmdclass={
        'clean': CleanCommand,
    },
    long_description=long_description,
    long_description_content_type='text/markdown'
)
