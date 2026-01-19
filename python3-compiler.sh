##############################
# Network Utilities on Linux #
# v1.1                       #
##############################
#!/bin/bash

#########################################
# Environment variable setting area     #
#########################################

# Make sure the alias is available in this shell script
# Sometimes, some key commands need to be provided using aliases to overload related instructions, such as docker, podman, kubectl.
# [Fixed] Sometimes the alias were defined in /etc/profile
shopt -s expand_aliases

#
# The configuration of environment variables and aliases takes effect immediately in the current shell environment.
#
if [ -f /etc/profile ]; then
   source /etc/profile
fi

if [ -f /etc/bashrc ]; then
   source /etc/bashrc
fi

if [ -f ~/.bash_profile ]; then
   source ~/.bash_profile
fi

if [ -f ~/.bashrc ]; then
   source ~/.bashrc
fi

if [ -f ~/.profile ]; then
   source ~/.profile
fi

#
# [Note] The working path is based on the actual path of the current script, not the current path. Therefore, using the tool's relative or absolute path access in any path will not cause any changes to the working path variable, this design ensures the stability of the working path.
#
WORKING_DIRECTORY=$(dirname $(realpath $0 2>/dev/null) 2>/dev/null)
if [ -z "${WORKING_DIRECTORY}" ]; then
   WORKING_DIRECTORY=$(pwd)
fi

# yum reinstall --downloadonly --downloaddir="${WORKING_DIRECTORY}" -y zlib-devel bzip2-devel openssl-devel ncurses-devel sqlite-devel readline-devel tk-devel gcc make libffi-devel pigz

DNF_DEPENDS=(
   zlib-devel
   bzip2-devel
   openssl-devel
   ncurses-devel
   sqlite-devel
   readline-devel
   tk-devel
   gcc
   make
   libffi-devel
   pigz
)

#
# [Note] Download all rpm depends. Deprecated methods: yum -y reinstall --downloadonly --downloaddir="${WORKING_DIRECTORY}" zlib-devel bzip2-devel openssl-devel ncurses-devel sqlite-devel readline-devel tk-devel gcc make libffi-devel pigz
#
download_depends() {

   echo 'hello'

   mkdir -p ${WORKING_DIRECTORY}/vendor/depends
   cd ${WORKING_DIRECTORY}/vendor/depends

   repotrack ${DNF_DEPENDS[@]}
}

install_depends() {

   # Ignore the configuration process of yum source
   yum -y install ${DNF_DEPENDS[@]}
}

download_decompress_source_archive() {

   local version=$(echo "${*}" | sed 's#--version ##g')

   if [ -z "$version" ]; then
      version='3.10.19'
   fi

   if [ ! -f "${WORKING_DIRECTORY}/vendor/python3/Python-$version.tgz" ]; then
      curl -o ${WORKING_DIRECTORY}/vendor/python3/Python-$version.tgz "https://www.python.org/ftp/python/$version/Python-$version.tgz"
   fi

   cd ${WORKING_DIRECTORY}/vendor/python3

   echo -n '[Info] Remove the original folder ... '
   /usr/bin/rm -rf Python-$version
   echo '[Done]'

   echo -n '[Info] Decompress the archive file ... '
   tar -I pigz -xf Python-$version.tgz
   echo '[Done]'

   du -s -h $(realpath Python-$version)
}

do_compile() {

   local version=$(echo "${*}" | sed 's#--version ##g')

   if [ -z "$version" ]; then
      version='3.10.19'
   fi

   if [ -d /usr/local/python-$version ]; then

      local n=$(find /usr/local/python-$version -maxdepth 1 -mindepth 1 2>/dev/null | wc -l)
      if [ $n -ne 0 ]; then
         echo "[Warn] The target folder is not empty."
         exit -1
      fi
   fi

   cd ${WORKING_DIRECTORY}/vendor/python3/Python-$version

   ./configure --enable-optimizations prefix=/usr/local/python-$version

   make -j$(nproc)

   make install
}

alternate_python3() {

   local version=$(echo "${*}" | sed 's#--version ##g')

   if [ -z "$version" ]; then
      version='3.10.19'
   fi

   local majorVersion=$(echo "$version" | awk -F'.' '{print $1"."$2}')

   update-alternatives --install /usr/bin/python3 python3 /usr/local/python-$version/bin/python$majorVersion 999

   update-alternatives --set python3 /usr/local/python-$version/bin/python$majorVersion

   alternatives --list 2>/dev/null | awk '$1 == "python3" || $1 == "pip3" {print $0}'
   
   python3 --version 2>/dev/null
   pip3 --version 2>/dev/null
}

alternate_pip3() {

   local version=$(echo "${*}" | sed 's#--version ##g')

   if [ -z "$version" ]; then
      version='3.10.19'
   fi

   local majorVersion=$(echo "$version" | awk -F'.' '{print $1"."$2}')

   update-alternatives --install /usr/bin/pip3 pip3 /usr/local/python-$version/bin/pip$majorVersion 999 2>/dev/null

   update-alternatives --set pip3 /usr/local/python-$version/bin/pip$majorVersion 2>/dev/null

   alternatives --list 2>/dev/null | awk '$1 == "python3" || $1 == "pip3" {print $0}'

   python3 --version 2>/dev/null
   pip3 --version 2>/dev/null
}

orderedPara=(
   "--download-depends"
   "--install-depends"
   "--download-decompress-source-archive"
   "--do-compile"
   "--alternate-python"
   "--alternate-pip"
   "--usage"
   "--help"
   "--manual"
)

declare -A mapParaFunc=(
   ["--download-depends"]="download_depends"
   ["--install-depends"]="install_depends"
   ["--download-decompress-source-archive"]="download_decompress_source_archive"
   ["--do-compile"]="do_compile"
   ["--alternate-python3"]="alternate_python3"
   ["--alternate-pip3"]="alternate_pip3"
   ["--usage"]="usage"
   ["--help"]="usage"
   ["--manual"]="usage"
)

declare -A mapParaSpec=(
   ["--download-depends"]="Download dependencies required by python3 compiling tasks, but do not install them."
   ["--install-depends"]="Install dependencies required by python3 compiling tasks."
   ["--download-decompress-source-archive"]="Download and decompress python3 source tarballs."
   ["--do-compile"]="Execute compilation."
   ["--alternate-python"]="Switch the Python 3 runtime environment to the current compiled version."
   ["--alternate-pip"]="Switch the PIP 3 version to the current compiled version."
   ["--usage"]="Operation Manual."
   ["--help"]="Operation Manual."
   ["--manual"]="Operation Manual."
)

usage() {
   echo '[Info] Python3 Compiler v1.1'
   echo '[Info] Verified on BCLinux 8.2'
   echo '[Usage]'

   for opt in ${orderedPara[@]}; do
      echo "   $0 $opt   ${mapParaSpec[$opt]}"
   done
}

if [ ! -z "$1" ] && [[ "${!mapParaFunc[@]}" =~ "$1" ]]; then
   INDEX_PARAM=$1
   shift
   eval "${mapParaFunc[${INDEX_PARAM}]} $@"
   exit 0
fi
