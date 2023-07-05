#
# src/Makefile.am
#
# For the license, see the COPYING file in the root directory.
#

SUBDIRS = \
	utils \
	swtpm

if !SHARED_LIBRARY_BUILD
SUBDIRS += \
	swtpm_bios \
	swtpm_cert \
	swtpm_ioctl \
	swtpm_localca \
	swtpm_setup
endif

if WITH_SELINUX
SUBDIRS += \
	selinux
endif
