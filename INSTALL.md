Install
===================

## Prerequisites
- GNU autotools/libtool
- libpcap or PF_RING (optional but recommended)
- [nDPI](http://www.ntop.org/products/deep-packet-inspection/ndpi/)

## autotools/libtool/libpcap
### On Ubuntu/Debian
```
# apt-get install build-essential
# apt-get install git autoconf automake autogen libpcap-dev libtool pkg-config
```

### On Fedora/CentOS
```
# yum install kernel-devel
# yum groupinstall "Development tools"
# yum install git autoconf automake autogen libpcap-devel libtool pkgconfig
```

## nDPI
### From source
```
$ git clone https://github.com/ntop/nDPI.git
$ cd nDPI
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install
```

### From package
```
$ sudo rpm -ivh https://forensics.cert.org/centos/cert/6.5/x86_64/nDPI-1.7.1-1.el6.x86_64.rpm
```

## PF_RING (optional but recommended)
Refer to [packages.ntop.org](http://packages.ntop.org/)

### On Ubuntu/Debian
```
$ wget http://apt-stable.ntop.org/14.04/all/apt-ntop-stable.deb
$ sudo dpkg -i apt-ntop-stable.deb
$ apt-get clean all
$ apt-get update
$ apt-get install pfring 
```

### On CentOS
```
# cat /etc/yum.repos.d/ntop.repo
[ntop]
name=ntop packages
baseurl=http://packages.ntop.org/centos-stable/$releasever/$basearch/
enabled=1
gpgcheck=1
gpgkey=http://packages.ntop.org/centos-stable/RPM-GPG-KEY-deri
[ntop-noarch]
name=ntop packages
baseurl=http://packages.ntop.org/centos-stable/$releasever/noarch/
enabled=1
gpgcheck=1
gpgkey=http://packages.ntop.org/centos-stable/RPM-GPG-KEY-deri
and also install the /etc/yum.repos.d/epel.repo extra repositories
# cat /etc/yum.repos.d/epel.repo 
[epel]
name=Extra Packages for Enterprise Linux X - $basearch
mirrorlist=https://mirrors.fedoraproject.org/metalink?repo=epel-X&arch=$basearch
failovermethod=priority
enabled=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-X
and
# cd /etc/yum.repos.d/
# wget https://copr.fedoraproject.org/coprs/saltstack/zeromq4/repo/epel-X/saltstack-zeromq4-epel-X.repo
```
Note: replace X with 6 (for CentOS 6) or 7 (for CentOS 7) then do:

then do:
```
# yum erase zeromq3 (Do this once to make sure zeromq3 is not installed)
# yum clean all
# yum update
# yum install pfring
```

