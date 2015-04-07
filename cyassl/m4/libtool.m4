# libtool.m4 - Configure libtool for the host system. -*-Autoconf-*-
#
#   Copyright (C) 1996, 1997, 1998, 1999, 2000, 2001, 2003, 2004, 2005,
#                 2006, 2007, 2008 Free Software Foundation, Inc.
#   Written by Gordon Matzigkeit, 1996
#
# This file is free software; the Free Software Foundation gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.

m4_define([_LT_COPYING], [dnl
#   Copyright (C) 1996, 1997, 1998, 1999, 2000, 2001, 2003, 2004, 2005,
#                 2006, 2007, 2008 Free Software Foundation, Inc.
#   Written by Gordon Matzigkeit, 1996
#
#   This file is part of GNU Libtool.
#
# GNU Libtool is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of
# the License, or (at your option) any later version.
#
# As a special exception to the GNU General Public License,
# if you distribute this file as part of a program or library that
# is built using GNU Libtool, you may include this file under the
# same distribution terms that you use for the rest of that program.
#
# GNU Libtool is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Libtool; see the file COPYING.  If not, a copy
# can be downloaded from http://www.gnu.org/licenses/gpl.html, or
# obtained by writing to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
])

# serial 56 LT_INIT


# LT_PREREQ(VERSION)
# ------------------
# Complain and exit if this libtool version is less that VERSION.
m4_defun([LT_PREREQ],
[m4_if(m4_version_compare(m4_defn([LT_PACKAGE_VERSION]), [$1]), -1,
       [m4_default([$3],
		   [m4_fatal([Libtool version $1 or higher is required],
		             63)])],
       [$2])])


# _LT_CHECK_BUILDDIR
# ------------------
# Complain if the absolute build directory name contains unusual characters
m4_defun([_LT_CHECK_BUILDDIR],
[case `pwd` in
  *\ * | *\	*)
    AC_MSG_WARN([Libtool does not cope well with whitespace in `pwd`]) ;;
esac
])


# LT_INIT([OPTIONS])
# ------------------
AC_DEFUN([LT_INIT],
[AC_PREREQ([2.58])dnl We use AC_INCLUDES_DEFAULT
AC_BEFORE([$0], [LT_LANG])dnl
AC_BEFORE([$0], [LT_OUTPUT])dnl
AC_BEFORE([$0], [LTDL_INIT])dnl
m4_require([_LT_CHECK_BUILDDIR])dnl

dnl Autoconf doesn't catch unexpanded LT_ macros by default:
m4_pattern_forbid([^_?LT_[A-Z_]+$])dnl
m4_pattern_allow([^(_LT_EOF|LT_DLGLOBAL|LT_DLLAZY_OR_NOW|LT_MULTI_MODULE)$])dnl
dnl aclocal doesn't pull ltoptions.m4, ltsugar.m4, or ltversion.m4
dnl unless we require an AC_DEFUNed macro:
AC_REQUIRE([LTOPTIONS_VERSION])dnl
AC_REQUIRE([LTSUGAR_VERSION])dnl
AC_REQUIRE([LTVERSION_VERSION])dnl
AC_REQUIRE([LTOBSOLETE_VERSION])dnl
m4_require([_LT_PROG_LTMAIN])dnl

dnl Parse OPTIONS
_LT_SET_OPTIONS([$0], [$1])

# This can be used to rebuild libtool when needed
LIBTOOL_DEPS="$ltmain"

# Always use our own libtool.
LIBTOOL='$(SHELL) $(top_builddir)/libtool'
AC_SUBST(LIBTOOL)dnl

_LT_SETUP

# Only expand once:
m4_define([LT_INIT])
])# LT_INIT

# Old names:
AU_ALIAS([AC_PROG_LIBTOOL], [LT_INIT])
AU_ALIAS([AM_PROG_LIBTOOL], [LT_INIT])
dnl aclocal-1.4 backwards compatibility:
dnl AC_DEFUN([AC_PROG_LIBTOOL], [])
dnl AC_DEFUN([AM_PROG_LIBTOOL], [])


# _LT_CC_BASENAME(CC)
# -------------------
# Calculate cc_basename.  Skip known compiler wrappers and cross-prefix.
m4_defun([_LT_CC_BASENAME],
[for cc_temp in $1""; do
  case $cc_temp in
    compile | *[[\\/]]compile | ccache | *[[\\/]]ccache ) ;;
    distcc | *[[\\/]]distcc | purify | *[[\\/]]purify ) ;;
    \-*) ;;
    *) break;;
  esac
done
cc_basename=`$ECHO "X$cc_temp" | $Xsed -e 's%.*/%%' -e "s%^$host_alias-%%"`
])


# _LT_FILEUTILS_DEFAULTS
# ----------------------
# It is okay to use these file commands and assume they have been set
# sensibly after `m4_require([_LT_FILEUTILS_DEFAULTS])'.
m4_defun([_LT_FILEUTILS_DEFAULTS],
[: ${CP="cp -f"}
: ${MV="mv -f"}
: ${RM="rm -f"}
])# _LT_FILEUTILS_DEFAULTS


# _LT_SETUP
# ---------
m4_defun([_LT_SETUP],
[AC_REQUIRE([AC_CANONICAL_HOST])dnl
AC_REQUIRE([AC_CANONICAL_BUILD])dnl
_LT_DECL([], [host_alias], [0], [The host system])dnl
_LT_DECL([], [host], [0])dnl
_LT_DECL([], [host_os], [0])dnl
dnl
_LT_DECL([], [build_alias], [0], [The build system])dnl
_LT_DECL([], [build], [0])dnl
_LT_DECL([], [build_os], [0])dnl
dnl
AC_REQUIRE([AC_PROG_CC])dnl
AC_REQUIRE([LT_PATH_LD])dnl
AC_REQUIRE([LT_PATH_NM])dnl
dnl
AC_REQUIRE([AC_PROG_LN_S])dnl
test -z "$LN_S" && LN_S="ln -s"
_LT_DECL([], [LN_S], [1], [Whether we need soft or hard links])dnl
dnl
AC_REQUIRE([LT_CMD_MAX_LEN])dnl
_LT_DECL([objext], [ac_objext], [0], [Object file suffix (normally "o")])dnl
_LT_DECL([], [exeext], [0], [Executable file suffix (normally "")])dnl
dnl
m4_require([_LT_FILEUTILS_DEFAULTS])dnl
m4_require([_LT_CHECK_SHELL_FEATURES])dnl
m4_require([_LT_CMD_RELOAD])dnl
m4_require([_LT_CHECK_MAGIC_METHOD])dnl
m4_require([_LT_CMD_OLD_ARCHIVE])dnl
m4_require([_LT_CMD_GLOBAL_SYMBOLS])dnl

_LT_CONFIG_LIBTOOL_INIT([
# See if we are running on zsh, and set the options which allow our
# commands through without removal of \ escapes INIT.
if test -n "\${ZSH_VERSION+set}" ; then
   setopt NO_GLOB_SUBST
fi
])
if test -n "${ZSH_VERSION+set}" ; then
   setopt NO_GLOB_SUBST
fi

_LT_CHECK_OBJDIR

m4_require([_LT_TAG_COMPILER])dnl
_LT_PROG_ECHO_BACKSLASH

case $host_os in
aix3*)
  # AIX sometimes has problems with the GCC collect2 program.  For some
  # reason, if we set the COLLECT_NAMES environment variable, the problems
  # vanish in a puff of smoke.
  if test "X${COLLECT_NAMES+set}" != Xset; then
    COLLECT_NAMES=
    export COLLECT_NAMES
  fi
  ;;
esac

# Sed substitution that helps us do robust quoting.  It backslashifies
# metacharacters that are still active within double-quoted strings.
sed_quote_subst='s/\([["`$\\]]\)/\\\1/g'

# Same as above, but do not quote variable references.
double_quote_subst='s/\([["`\\]]\)/\\\1/g'

# Sed substitution to delay expansion of an escaped shell variable in a
# double_quote_subst'ed string.
delay_variable_subst='s/\\\\\\\\\\\$/\\\\\\$/g'

# Sed substitution to delay expansion of an escaped single quote.
delay_single_quote_subst='s/'\''/'\'\\\\\\\'\''/g'

# Sed substitution to avoid accidental globbing in evaled expressions
no_glob_subst='s/\*/\\\*/g'

# Global variables:
ofile=libtool
can_build_shared=yes

# All known linkers require a `.a' archive for static linking (except MSVC,
# which needs '.lib').
libext=a

with_gnu_ld="$lt_cv_prog_gnu_ld"

old_CC="$CC"
old_CFLAGS="$CFLAGS"

# Set sane defaults for various variables
test -z "$CC" && CC=cc
test -z "$LTCC" && LTCC=$CC
test -z "$LTCFLAGS" && LTCFLAGS=$CFLAGS
test -z "$LD" && LD=ld
test -z "$ac_objext" && ac_objext=o

_LT_CC_BASENAME([$compiler])

# Only perform the check for file, if the check method requires it
test -z "$MAGIC_CMD" && MAGIC_CMD=file
case $deplibs_check_method in
file_magic*)
  if test "$file_magic_cmd" = '$MAGIC_CMD'; then
    _LT_PATH_MAGIC
  fi
  ;;
esac

# Use C for the default configuration in the libtool script
LT_SUPPORTED_TAG([CC])
_LT_LANG_C_CONFIG
_LT_LANG_DEFAULT_CONFIG
_LT_CONFIG_COMMANDS
])# _LT_SETUP


# _LT_PROG_LTMAIN
# ---------------
# Note that this code is called both from `configure', and `config.status'
# now that we use AC_CONFIG_COMMANDS to generate libtool.  Notably,
# `config.status' has no value for ac_aux_dir unless we are using Automake,
# so we pass a copy along to make sure it has a sensible value anyway.
m4_defun([_LT_PROG_LTMAIN],
[m4_ifdef([AC_REQUIRE_AUX_FILE], [AC_REQUIRE_AUX_FILE([ltmain.sh])])dnl
_LT_CONFIG_LIBTOOL_INIT([ac_aux_dir='$ac_aux_dir'])
ltmain="$ac_aux_dir/ltmain.sh"
])# _LT_PROG_LTMAIN


## ------------------------------------- ##
## Accumulate code for creating libtool. ##
## ------------------------------------- ##

# So that we can recreate a full libtool script including additional
# tags, we accumulate the chunks of code to send to AC_CONFIG_COMMANDS
# in macros and then make a single call at the end using the `libtool'
# label.


# _LT_CONFIG_LIBTOOL_INIT([INIT-COMMANDS])
# ----------------------------------------
# Register INIT-COMMANDS to be passed to AC_CONFIG_COMMANDS later.
m4_define([_LT_CONFIG_LIBTOOL_INIT],
[m4_ifval([$1],
          [m4_append([_LT_OUTPUT_LIBTOOL_INIT],
                     [$1
])])])

# Initialize.
m4_define([_LT_OUTPUT_LIBTOOL_INIT])


# _LT_CONFIG_LIBTOOL([COMMANDS])
# ------------------------------
# Register COMMANDS to be passed to AC_CONFIG_COMMANDS later.
m4_define([_LT_CONFIG_LIBTOOL],
[m4_ifval([$1],
          [m4_append([_LT_OUTPUT_LIBTOOL_COMMANDS],
                     [$1
])])])

# Initialize.
m4_define([_LT_OUTPUT_LIBTOOL_COMMANDS])


# _LT_CONFIG_SAVE_COMMANDS([COMMANDS], [INIT_COMMANDS])
# -----------------------------------------------------
m4_defun([_LT_CONFIG_SAVE_COMMANDS],
[_LT_CONFIG_LIBTOOL([$1])
_LT_CONFIG_LIBTOOL_INIT([$2])
])


# _LT_FORMAT_COMMENT([COMMENT])
# -----------------------------
# Add leading comment marks to the start of each line, and a trailing
# full-stop to the whole comment if one is not present already.
m4_define([_LT_FORMAT_COMMENT],
[m4_ifval([$1], [
m4_bpatsubst([m4_bpatsubst([$1], [^ *], [# ])],
              [['`$\]], [\\\&])]m4_bmatch([$1], [[!?.]$], [], [.])
)])



## ------------------------ ##
## FIXME: Eliminate VARNAME ##
## ------------------------ ##


# _LT_DECL([CONFIGNAME], VARNAME, VALUE, [DESCRIPTION], [IS-TAGGED?])
# -------------------------------------------------------------------
# CONFIGNAME is the name given to the value in the libtool script.
# VARNAME is the (base) name used in the configure script.
# VALUE may be 0, 1 or 2 for a computed quote escaped value based on
# VARNAME.  Any other value will be used directly.
m4_define([_LT_DECL],
[lt_if_append_uniq([lt_decl_varnames], [$2], [, ],
    [lt_dict_add_subkey([lt_decl_dict], [$2], [libtool_name],
	[m4_ifval([$1], [$1], [$2])])
    lt_dict_add_subkey([lt_decl_dict], [$2], [value], [$3])
    m4_ifval([$4],
	[lt_dict_add_subkey([lt_decl_dict], [$2], [description], [$4])])
    lt_dict_add_subkey([lt_decl_dict], [$2],
	[tagged?], [m4_ifval([$5], [yes], [no])])])
])


# _LT_TAGDECL([CONFIGNAME], VARNAME, VALUE, [DESCRIPTION])
# --------------------------------------------------------
m4_define([_LT_TAGDECL], [_LT_DECL([$1], [$2], [$3], [$4], [yes])])


# lt_decl_tag_varnames([SEPARATOR], [VARNAME1...])
# ------------------------------------------------
m4_define([lt_decl_tag_varnames],
[_lt_decl_filter([tagged?], [yes], $@)])


# _lt_decl_filter(SUBKEY, VALUE, [SEPARATOR], [VARNAME1..])
# ---------------------------------------------------------
m4_define([_lt_decl_filter],
[m4_case([$#],
  [0], [m4_fatal([$0: too few arguments: $#])],
  [1], [m4_fatal([$0: too few arguments: $#: $1])],
  [2], [lt_dict_filter([lt_decl_dict], [$1], [$2], [], lt_decl_varnames)],
  [3], [lt_dict_filter([lt_decl_dict], [$1], [$2], [$3], lt_decl_varnames)],
  [lt_dict_filter([lt_decl_dict], $@)])[]dnl
])


# lt_decl_quote_varnames([SEPARATOR], [VARNAME1...])
# --------------------------------------------------
m4_define([lt_decl_quote_varnames],
[_lt_decl_filter([value], [1], $@)])


# lt_decl_dquote_varnames([SEPARATOR], [VARNAME1...])
# ---------------------------------------------------
m4_define([lt_decl_dquote_varnames],
[_lt_decl_filter([value], [2], $@)])


# lt_decl_varnames_tagged([SEPARATOR], [VARNAME1...])
# ---------------------------------------------------
m4_define([lt_decl_varnames_tagged],
[m4_assert([$# <= 2])dnl
_$0(m4_quote(m4_default([$1], [[, ]])),
    m4_ifval([$2], [[$2]], [m4_dquote(lt_decl_tag_varnames)]),
    m4_split(m4_normalize(m4_quote(_LT_TAGS)), [ ]))])
m4_define([_lt_decl_varnames_tagged],
[m4_ifval([$3], [lt_combine([$1], [$2], [_], $3)])])


# lt_decl_all_varnames([SEPARATOR], [VARNAME1...])
# ------------------------------------------------
m4_define([lt_decl_all_varnames],
[_$0(m4_quote(m4_default([$1], [[, ]])),
     m4_if([$2], [],
	   m4_quote(lt_decl_varnames),
	m4_quote(m4_shift($@))))[]dnl
])
m4_define([_lt_decl_all_varnames],
[lt_join($@, lt_decl_varnames_tagged([$1],
			lt_decl_tag_varnames([[, ]], m4_shift($@))))dnl
])


# _LT_CONFIG_STATUS_DECLARE([VARNAME])
# ------------------------------------
# Quote a variable value, and forward it to `config.status' so that its
# declaration there will have the same value as in `configure'.  VARNAME
# must have a single quote delimited value for this to work.
m4_define([_LT_CONFIG_STATUS_DECLARE],
[$1='`$ECHO "X$][$1" | $Xsed -e "$delay_single_quote_subst"`'])


# _LT_CONFIG_STATUS_DECLARATIONS
# ------------------------------
# We delimit libtool config variables with single quotes, so when
# we write them to config.status, we have to be sure to quote all
# embedded single quotes properly.  In configure, this macro expands
# each variable declared with _LT_DECL (and _LT_TAGDECL) into:
#
#    <var>='`$ECHO "X$<var>" | $Xsed -e "$delay_single_quote_subst"`'
m4_defun([_LT_CONFIG_STATUS_DECLARATIONS],
[m4_foreach([_lt_var], m4_quote(lt_decl_all_varnames),
    [m4_n([_LT_CONFIG_STATUS_DECLARE(_lt_var)])])])


# _LT_LIBTOOL_TAGS
# ----------------
# Output comment and list of tags supported by the script
m4_defun([_LT_LIBTOOL_TAGS],
[_LT_FORMAT_COMMENT([The names of the tagged configurations supported by this script])dnl
available_tags="_LT_TAGS"dnl
])


# _LT_LIBTOOL_DECLARE(VARNAME, [TAG])
# -----------------------------------
# Extract the dictionary values for VARNAME (optionally with TAG) and
# expand to a commented shell variable setting:
#
#    # Some comment about what VAR is for.
#    visible_name=$lt_internal_name
m4_define([_LT_LIBTOOL_DECLARE],
[_LT_FORMAT_COMMENT(m4_quote(lt_dict_fetch([lt_decl_dict], [$1],
					   [description])))[]dnl
m4_pushdef([_libtool_name],
    m4_quote(lt_dict_fetch([lt_decl_dict], [$1], [libtool_name])))[]dnl
m4_case(m4_quote(lt_dict_fetch([lt_decl_dict], [$1], [value])),
    [0], [_libtool_name=[$]$1],
    [1], [_libtool_name=$lt_[]$1],
    [2], [_libtool_name=$lt_[]$1],
    [_libtool_name=lt_dict_fetch([lt_decl_dict], [$1], [value])])[]dnl
m4_ifval([$2], [_$2])[]m4_popdef([_libtool_name])[]dnl
])


# _LT_LIBTOOL_CONFIG_VARS
# -----------------------
# Produce commented declarations of non-tagged libtool config variables
# suitable for insertion in the LIBTOOL CONFIG section of the `libtool'
# script.  Tagged libtool config variables (even for the LIBTOOL CONFIG
# section) are produced by _LT_LIBTOOL_TAG_VARS.
m4_defun([_LT_LIBTOOL_CONFIG_VARS],
[m4_foreach([_lt_var],
    m4_quote(_lt_decl_filter([tagged?], [no], [], lt_decl_varnames)),
    [m4_n([_LT_LIBTOOL_DECLARE(_lt_var)])])])


# _LT_LIBTOOL_TAG_VARS(TAG)
# -------------------------
m4_define([_LT_LIBTOOL_TAG_VARS],
[m4_foreach([_lt_var], m4_quote(lt_decl_tag_varnames),
    [m4_n([_LT_LIBTOOL_DECLARE(_lt_var, [$1])])])])


# _LT_TAGVAR(VARNAME, [TAGNAME])
# ------------------------------
m4_define([_LT_TAGVAR], [m4_ifval([$2], [$1_$2], [$1])])


# _LT_CONFIG_COMMANDS
# -------------------
# Send accumulated output to $CONFIG_STATUS.  Thanks to the lists of
# variables for single and double quote escaping we saved from calls
# to _LT_DECL, we can put quote escaped variables declarations
# into `config.status', and then the shell code to quote escape them in
# for loops in `config.status'.  Finally, any additional code accumulated
# from calls to _LT_CONFIG_LIBTOOL_INIT is expanded.
m4_defun([_LT_CONFIG_COMMANDS],
[AC_PROVIDE_IFELSE([LT_OUTPUT],
	dnl If the libtool generation code has been placed in $CONFIG_LT,
	dnl instead of duplicating it all over again into config.status,
	dnl then we will have config.status run $CONFIG_LT later, so it
	dnl needs to know what name is stored there:
        [AC_CONFIG_COMMANDS([libtool],
            [$SHELL $CONFIG_LT || AS_EXIT(1)], [CONFIG_LT='$CONFIG_LT'])],
    dnl If the libtool generation code is destined for config.status,
    dnl expand the accumulated commands and init code now:
    [AC_CONFIG_COMMANDS([libtool],
        [_LT_OUTPUT_LIBTOOL_COMMANDS], [_LT_OUTPUT_LIBTOOL_COMMANDS_INIT])])
])#_LT_CONFIG_COMMANDS


# Initialize.
m4_define([_LT_OUTPUT_LIBTOOL_COMMANDS_INIT],
[

# The HP-UX ksh and POSIX shell print the target directory to stdout
# if CDPATH is set.
(unset CDPATH) >/dev/null 2>&1 && unset CDPATH

sed_quote_subst='$sed_quote_subst'
double_quote_subst='$double_quote_subst'
delay_variable_subst='$delay_variable_subst'
_LT_CONFIG_STATUS_DECLARATIONS
LTCC='$LTCC'
LTCFLAGS='$LTCFLAGS'
compiler='$compiler_DEFAULT'

# Quote evaled strings.
for var in lt_decl_all_varnames([[ \
]], lt_decl_quote_varnames); do
    case \`eval \\\\\$ECHO "X\\\\\$\$var"\` in
    *[[\\\\\\\`\\"\\\$]]*)
      eval "lt_\$var=\\\\\\"\\\`\\\$ECHO \\"X\\\$\$var\\" | \\\$Xsed -e \\"\\\$sed_quote_subst\\"\\\`\\\\\\""
      ;;
    *)
      eval "lt_\$var=\\\\\\"\\\$\$var\\\\\\""
      ;;
    esac
done

# Double-quote double-evaled strings.
for var in lt_decl_all_varnames([[ \
]], lt_decl_dquote_varnames); do
    case \`eval \\\\\$ECHO "X\\\\\$\$var"\` in
    *[[\\\\\\\`\\"\\\$]]*)
      eval "lt_\$var=\\\\\\"\\\`\\\$ECHO \\"X\\\$\$var\\" | \\\$Xsed -e \\"\\\$double_quote_subst\\" -e \\"\\\$sed_quote_subst\\" -e \\"\\\$delay_variable_subst\\"\\\`\\\\\\""
      ;;
    *)
      eval "lt_\$var=\\\\\\"\\\$\$var\\\\\\""
      ;;
    esac
done

# Fix-up fallback echo if it was mangled by the above quoting rules.
case \$lt_ECHO in
*'\\\[$]0 --fallback-echo"')dnl "
  lt_ECHO=\`\$ECHO "X\$lt_ECHO" | \$Xsed -e 's/\\\\\\\\\\\\\\\[$]0 --fallback-echo"\[$]/\[$]0 --fallback-echo"/'\`
  ;;
esac

_LT_OUTPUT_LIBTOOL_INIT
])


# LT_OUTPUT
# ---------
# This macro allows early generation of the libtool script (before
# AC_OUTPUT is called), incase it is used in configure for compilation
# tests.
AC_DEFUN([LT_OUTPUT],
[: ${CONFIG_LT=./config.lt}
AC_MSG_NOTICE([creating $CONFIG_LT])
cat >"$CONFIG_LT" <<_LTEOF
#! $SHELL
# Generated by $as_me.
# Run this file to recreate a libtool stub with the current configuration.

lt_cl_silent=false
SHELL=\${CONFIG_SHELL-$SHELL}
_LTEOF

cat >>"$CONFIG_LT" <<\_LTEOF
AS_SHELL_SANITIZE
_AS_PREPARE

exec AS_MESSAGE_FD>&1
exec AS_MESSAGE_LOG_FD>>config.log
{
  echo
  AS_BOX([Running $as_me.])
} >&AS_MESSAGE_LOG_FD

lt_cl_help="\
\`$as_me' creates a local libtool stub from the current configuration,
for use in further configure time tests before the real libtool is
generated.

Usage: $[0] [[OPTIONS]]

  -h, --help      print this help, then exit
  -V, --version   print version number, then exit
  -q, --quiet     do not print progress messages
  -d, --debug     don't remove temporary files

Report bugs to <bug-libtool@gnu.org>."

lt_cl_version="\
m4_ifset([AC_PACKAGE_NAME], [AC_PACKAGE_NAME ])config.lt[]dnl
m4_ifset([AC_PACKAGE_VERSION], [ AC_PACKAGE_VERSION])
configured by $[0], generated by m4_PACKAGE_STRING.

Copyright (C) 2008 Free Software Foundation, Inc.
This config.lt script is free software; the Free Software Foundation
gives unlimited permision to copy, distribute and modify it."

while test $[#] != 0
do
  case $[1] in
    --version | --v* | -V )
      echo "$lt_cl_version"; exit 0 ;;
    --help | --h* | -h )
      echo "$lt_cl_help"; exit 0 ;;
    --debug | --d* | -d )
      debug=: ;;
    --quiet | --q* | --silent | --s* | -q )
      lt_cl_silent=: ;;

    -*) AC_MSG_ERROR([unrecognized option: $[1]
Try \`$[0] --help' for more information.]) ;;

    *) AC_MSG_ERROR([unrecognized argument: $[1]
Try \`$[0] --help' for more information.]) ;;
  esac
  shift
done

if $lt_cl_silent; then
  exec AS_MESSAGE_FD>/dev/null
fi
_LTEOF

cat >>"$CONFIG_LT" <<_LTEOF
_LT_OUTPUT_LIBTOOL_COMMANDS_INIT
_LTEOF

cat >>"$CONFIG_LT" <<\_LTEOF
AC_MSG_NOTICE([creating $ofile])
_LT_OUTPUT_LIBTOOL_COMMANDS
AS_EXIT(0)
_LTEOF
chmod +x "$CONFIG_LT"

# configure is writing to config.log, but config.lt does its own redirection,
# appending to config.log, which fails on DOS, as config.log is still kept
# open by configure.  Here we exec the FD to /dev/null, effectively closing
# config.log, so it can be properly (re)opened and appended to by config.lt.
if test "$no_create" != yes; then
  lt_cl_success=:
  test "$silent" = yes &&
    lt_config_lt_args="$lt_config_lt_args --quiet"
  exec AS_MESSAGE_LOG_FD>/dev/null
  $SHELL "$CONFIG_LT" $lt_config_lt_args || lt_cl_success=false
  exec AS_MESSAGE_LOG_FD>>config.log
  $lt_cl_success || AS_EXIT(1)
fi
])# LT_OUTPUT


# _LT_CONFIG(TAG)
# ---------------
# If TAG is the built-in tag, create an initial libtool script with a
# default configuration from the untagged config vars.  Otherwise add code
# to config.status for appending the configuration named by TAG from the
# matching tagged config vars.
m4_defun([_LT_CONFIG],
[m4_require([_LT_FILEUTILS_DEFAULTS])dnl
_LT_CONFIG_SAVE_COMMANDS([
  m4_define([_LT_TAG], m4_if([$1], [], [C], [$1]))dnl
  m4_if(_LT_TAG, [C], [
    # See if we are running on zsh, and set the options which allow our
    # commands through without removal of \ escapes.
    if test -n "${ZSH_VERSION+set}" ; then
      setopt NO_GLOB_SUBST
    fi

    cfgfile="${ofile}T"
    trap "$RM \"$cfgfile\"; exit 1" 1 2 15
    $RM "$cfgfile"

    cat <<_LT_EOF >> "$cfgfile"
#! $SHELL

# `$ECHO "$ofile" | sed 's%^.*/%%'` - Provide generalized library-building support services.
# Generated automatically by $as_me ($PACKAGE$TIMESTAMP) $VERSION
# Libtool was configured on host `(hostname || uname -n) 2>/dev/null | sed 1q`:
# NOTE: Changes made to this file will be lost: look at ltmain.sh.
#
_LT_COPYING
_LT_LIBTOOL_TAGS

# ### BEGIN LIBTOOL CONFIG
_LT_LIBTOOL_CONFIG_VARS
_LT_LIBTOOL_TAG_VARS
# ### END LIBTOOL CONFIG

_LT_EOF

  case $host_os in
  aix3*)
    cat <<\_LT_EOF >> "$cfgfile"
# AIX sometimes has problems with the GCC collect2 program.  For some
# reason, if we set the COLLECT_NAMES environment variable, the problems
# vanish in a puff of smoke.
if test "X${COLLECT_NAMES+set}" != Xset; then
  COLLECT_NAMES=
  export COLLECT_NAMES
fi
_LT_EOF
    ;;
  esac

  _LT_PROG_LTMAIN

  # We use sed instead of cat because bash on DJGPP gets confused if
  # if finds mixed CR/LF and LF-only lines.  Since sed operates in
  # text mode, it properly converts lines to CR/LF.  This bash problem
  # is reportedly fixed, but why not run on old versions too?
  sed '/^# Generated shell functions inserted here/q' "$ltmain" >> "$cfgfile" \
    || (rm -f "$cfgfile"; exit 1)

  _LT_PROG_XSI_SHELLFNS

  sed -n '/^# Generated shell functions inserted here/,$p' "$ltmain" >> "$cfgfile" \
    || (rm -f "$cfgfile"; exit 1)

  mv -f "$cfgfile" "$ofile" ||
    (rm -f "$ofile" && cp "$cfgfile" "$ofile" && rm -f "$cfgfile")
  chmod +x "$ofile"
],
[cat <<_LT_EOF >> "$ofile"

dnl Unfortunately we have to use $1 here, since _LT_TAG is not expanded
dnl in a comment (ie after a #).
# ### BEGIN LIBTOOL TAG CONFIG: $1
_LT_LIBTOOL_TAG_VARS(_LT_TAG)
# ### END LIBTOOL TAG CONFIG: $1
_LT_EOF
])dnl /m4_if
],
[m4_if([$1], [], [
    PACKAGE='$PACKAGE'
    VERSION='$VERSION'
    TIMESTAMP='$TIMESTAMP'
    RM='$RM'
    ofile='$ofile'], [])
])dnl /_LT_CONFIG_SAVE_COMMANDS
])# _LT_CONFIG


# LT_SUPPORTED_TAG(TAG)
# ---------------------
# Trace this macro to discover what tags are supported by the libtool
# --tag option, using:
#    autoconf --trace 'LT_SUPPORTED_TAG:$1'
AC_DEFUN([LT_SUPPORTED_TAG], [])


# C support is built-in for now
m4_define([_LT_LANG_C_enabled], [])
m4_define([_LT_TAGS], [])


# LT_LANG(LANG)
# -------------
# Enable libtool support for the given language if not already enabled.
AC_DEFUN([LT_LANG],
[AC_BEFORE([$0], [LT_OUTPUT])dnl
m4_case([$1],
  [C],			[_LT_LANG(C)],
  [C++],		[_LT_LANG(CXX)],
  [Java],		[_LT_LANG(GCJ)],
  [Fortran 77],		[_LT_LANG(F77)],
  [Fortran],		[_LT_LANG(FC)],
  [Windows Resource],	[_LT_LANG(RC)],
  [m4_ifdef([_LT_LANG_]$1[_CONFIG],
    [_LT_LANG($1)],
    [m4_fatal([$0: unsupported language: "$1"])])])dnl
])# LT_LANG


# _LT_LANG(LANGNAME)
# ------------------
m4_defun([_LT_LANG],
[m4_ifdef([_LT_LANG_]$1[_enabled], [],
  [LT_SUPPORTED_TAG([$1])dnl
  m4_append([_LT_TAGS], [$1 ])dnl
  m4_define([_LT_LANG_]$1[_enabled], [])dnl
  _LT_LANG_$1_CONFIG($1)])dnl
])# _LT_LANG


# _LT_LANG_DEFAULT_CONFIG
# -----------------------
m4_defun([_LT_LANG_DEFAULT_CONFIG],
[AC_PROVIDE_IFELSE([AC_PROG_CXX],
  [LT_LANG(CXX)],
  [m4_define([AC_PROG_CXX], defn([AC_PROG_CXX])[LT_LANG(CXX)])])

AC_PROVIDE_IFELSE([AC_PROG_F77],
  [LT_LANG(F77)],
  [m4_define([AC_PROG_F77], defn([AC_PROG_F77])[LT_LANG(F77)])])

AC_PROVIDE_IFELSE([AC_PROG_FC],
  [LT_LANG(FC)],
  [m4_define([AC_PROG_FC], defn([AC_PROG_FC])[LT_LANG(FC)])])

dnl The call to [A][M_PROG_GCJ] is quoted like that to stop aclocal
dnl pulling things in needlessly.
AC_PROVIDE_IFELSE([AC_PROG_GCJ],
  [LT_LANG(GCJ)],
  [AC_PROVIDE_IFELSE([A][M_PROG_GCJ],
    [LT_LANG(GCJ)],
    [AC_PROVIDE_IFELSE([LT_PROG_GCJ],
      [LT_LANG(GCJ)],
      [m4_ifdef([AC_PROG_GCJ],
	[m4_define([AC_PROG_GCJ], defn([AC_PROG_GCJ])[LT_LANG(GCJ)])])
       m4_ifdef([A][M_PROG_GCJ],
	[m4_define([A][M_PROG_GCJ], defn([A][M_PROG_GCJ])[LT_LANG(GCJ)])])
       m4_ifdef([LT_PROG_GCJ],
	[m4_define([LT_PROG_GCJ], defn([LT_PROG_GCJ])[LT_LANG(GCJ)])])])])])

AC_PROVIDE_IFELSE([LT_PROG_RC],
  [LT_LANG(RC)],
  [m4_define([LT_PROG_RC], defn([LT_PROG_RC])[LT_LANG(RC)])])
])# _LT_LANG_DEFAULT_CONFIG

# Obsolete macros:
AU_DEFUN([AC_LIBTOOL_CXX], [LT_LANG(C++)])
AU_DEFUN([AC_LIBTOOL_F77], [LT_LANG(Fortran 77)])
AU_DEFUN([AC_LIBTOOL_FC], [LT_LANG(Fortran)])
AU_DEFUN([AC_LIBTOOL_GCJ], [LT_LANG(Java)])
dnl aclocal-1.4 backwards compatibility:
dnl AC_DEFUN([AC_LIBTOOL_CXX], [])
dnl AC_DEFUN([AC_LIBTOOL_F77], [])
dnl AC_DEFUN([AC_LIBTOOL_FC], [])
dnl AC_DEFUN([AC_LIBTOOL_GCJ], [])


# _LT_TAG_COMPILER
# ----------------
m4_defun([_LT_TAG_COMPILER],
[AC_REQUIRE([AC_PROG_CC])dnl

_LT_DECL([LTCC], [CC], [1], [A C compiler])dnl
_LT_DECL([LTCFLAGS], [CFLAGS], [1], [LTCC compiler flags])dnl
_LT_TAGDECL([CC], [compiler], [1], [A language specific compiler])dnl
_LT_TAGDECL([with_gcc], [GCC], [0], [Is the compiler the GNU compiler?])dnl

# If no C compiler was specified, use CC.
LTCC=${LTCC-"$CC"}

# If no C compiler flags were specified, use CFLAGS.
LTCFLAGS=${LTCFLAGS-"$CFLAGS"}

# Allow CC to be a program name with arguments.
compiler=$CC
])# _LT_TAG_COMPILER


# _LT_COMPILER_BOILERPLATE
# ------------------------
# Check for compiler boilerplate output or warnings with
# the simple compiler test code.
m4_defun([_LT_COMPILER_BOILERPLATE],
[m4_require([_LT_DECL_SED])dnl
ac_outfile=conftest.$ac_objext
echo "$lt_simple_compile_test_code" >conftest.$ac_ext
eval "$ac_compile" 2>&1 >/dev/null | $SED '/^$/d; /^ *+/d' >conftest.err
_lt_compiler_boilerplate=`cat conftest.err`
$RM conftest*
])# _LT_COMPILER_BOILERPLATE


# _LT_LINKER_BOILERPLATE
# ----------------------
# Check for linker boilerplate output or warnings with
# the simple link test code.
m4_defun([_LT_LINKER_BOILERPLATE],
[m4_require([_LT_DECL_SED])dnl
ac_outfile=conftest.$ac_objext
echo "$lt_simple_link_test_code" >conftest.$ac_ext
eval "$ac_link" 2>&1 >/dev/null | $SED '/^$/d; /^ *+/d' >conftest.err
_lt_linker_boilerplate=`cat conftest.err`
$RM -r conftest*
])# _LT_LINKER_BOILERPLATE

# _LT_REQUIRED_DARWIN_CHECKS
# -------------------------
m4_defun_once([_LT_REQUIRED_DARWIN_CHECKS],[
  case $host_os in
    rhapsody* | darwin*)
    AC_CHECK_TOOL([DSYMUTIL], [dsymutil], [:])
    AC_CHECK_TOOL([NMEDIT], [nmedit], [:])
    AC_CHECK_TOOL([LIPO], [lipo], [:])
    AC_CHECK_TOOL([OTOOL], [otool], [:])
    AC_CHECK_TOOL([OTOOL64], [otool64], [:])
    _LT_DECL([], [DSYMUTIL], [1],
      [Tool to manipulate archived DWARF debug symbol files on Mac OS X])
    _LT_DECL([], [NMEDIT], [1],
      [Tool to change global to local symbols on Mac OS X])
    _LT_DECL([], [LIPO], [1],
      [Tool to manipulate fat objects and archives on Mac OS X])
    _LT_DECL([], [OTOOL], [1],
      [ldd/readelf like tool for Mach-O binaries on Mac OS X])
    _LT_DECL([], [OTOOL64], [1],
      [ldd/readelf like tool for 64 bit Mach-O binaries on Mac OS X 10.4])

    AC_CACHE_CHECK([for -single_module linker flag],[lt_cv_apple_cc_single_mod],
      [lt_cv_apple_cc_single_mod=no
      if test -z "${LT_MULTI_MODULE}"; then
	# By default we will add the -single_module flag. You can override
	# by either setting the environment variable LT_MULTI_MODULE
	# non-empty at configure time, or by adding -multi_module to the
	# link flags.
	rm -rf libconftest.dylib*
	echo "int foo(void){return 1;}" > conftest.c
	echo "$LTCC $LTCFLAGS $LDFLAGS -o libconftest.dylib \
-dynamiclib -Wl,-single_module conftest.c" >&AS_MESSAGE_LOG_FD
	$LTCC $LTCFLAGS $LDFLAGS -o libconftest.dylib \
	  -dynamiclib -Wl,-single_module conftest.c 2>conftest.err
        _lt_result=$?
	if test -f libconftest.dylib && test ! -s conftest.err && test $_lt_result = 0; then
	  lt_cv_apple_cc_single_mod=yes
	else
	  cat conftest.err >&AS_MESSAGE_LOG_FD
	fi
	rm -rf libconftest.dylib*
	rm -f conftest.*
      fi])
    AC_CACHE_CHECK([for -exported_symbols_list linker flag],
      [lt_cv_ld_exported_symbols_list],
      [lt_cv_ld_exported_symbols_list=no
      save_LDFLAGS=$LDFLAGS
      echo "_main" > conftest.sym
      LDFLAGS="$LDFLAGS -Wl,-exported_symbols_list,conftest.sym"
      AC_LINK_IFELSE([AC_LANG_PROGRAM([],[])],
	[lt_cv_ld_exported_symbols_list=yes],
	[lt_cv_ld_exported_symbols_list=no])
	LDFLAGS="$save_LDFLAGS"
    ])
    case $host_os in
    rhapsody* | darwin1.[[012]])
      _lt_dar_allow_undefined='${wl}-undefined ${wl}suppress' ;;
    darwin1.*)
      _lt_dar_allow_undefined='${wl}-flat_namespace ${wl}-undefined ${wl}suppress' ;;
    darwin*) # darwin 5.x on
      # if running on 10.5 or later, the deployment target defaults
      # to the OS version, if on x86, and 10.4, the deployment
      # target defaults to 10.4. Don't you love it?
      case ${MACOSX_DEPLOYMENT_TARGET-10.0},$host in
	10.0,*86*-darwin8*|10.0,*-darwin[[91]]*)
	  _lt_dar_allow_undefined='${wl}-undefined ${wl}dynamic_lookup' ;;
	10.[[012]]*)
	  _lt_dar_allow_undefined='${wl}-flat_namespace ${wl}-undefined ${wl}suppress' ;;
	10.*)
	  _lt_dar_allow_undefined='${wl}-undefined ${wl}dynamic_lookup' ;;
      esac
    ;;
  esac
    if test "$lt_cv_apple_cc_single_mod" = "yes"; then
      _lt_dar_single_mod='$single_module'
    fi
    if test "$lt_cv_ld_exported_symbols_list" = "yes"; then
      _lt_dar_export_syms=' ${wl}-exported_symbols_list,$output_objdir/${libname}-symbols.expsym'
    else
      _lt_dar_export_syms='~$NMEDIT -s $output_objdir/${libname}-symbols.expsym ${lib}'
    fi
    if test "$DSYMUTIL" != ":"; then
      _lt_dsymutil='~$DSYMUTIL $lib || :'
    else
      _lt_dsymutil=
    fi
    ;;
  esac
])


# _LT_DARWIN_LINKER_FEATURES
# --------------------------
# Checks for linker and compiler features on darwin
m4_defun([_LT_DARWIN_LINKER_FEATURES],
[
  m4_require([_LT_REQUIRED_DARWIN_CHECKS])
  _LT_TAGVAR(archive_cmds_need_lc, $1)=no
  _LT_TAGVAR(hardcode_direct, $1)=no
  _LT_TAGVAR(hardcode_automatic, $1)=yes
  _LT_TAGVAR(hardcode_shlibpath_var, $1)=unsupported
  _LT_TAGVAR(whole_archive_flag_spec, $1)=''
  _LT_TAGVAR(link_all_deplibs, $1)=yes
  _LT_TAGVAR(allow_undefined_flag, $1)="$_lt_dar_allow_undefined"
  case $cc_basename in
     ifort*) _lt_dar_can_shared=yes ;;
     *) _lt_dar_can_shared=$GCC ;;
  esac
  if test "$_lt_dar_can_shared" = "yes"; then
    output_verbose_link_cmd=echo
    _LT_TAGVAR(archive_cmds, $1)="\$CC -dynamiclib \$allow_undefined_flag -o \$lib \$libobjs \$deplibs \$compiler_flags -install_name \$rpath/\$soname \$verstring $_lt_dar_single_mod${_lt_dsymutil}"
    _LT_TAGVAR(module_cmds, $1)="\$CC \$allow_undefined_flag -o \$lib -bundle \$libobjs \$deplibs \$compiler_flags${_lt_dsymutil}"
    _LT_TAGVAR(archive_expsym_cmds, $1)="sed 's,^,_,' < \$export_symbols > \$output_objdir/\${libname}-symbols.expsym~\$CC -dynamiclib \$allow_undefined_flag -o \$lib \$libobjs \$deplibs \$compiler_flags -install_name \$rpath/\$soname \$verstring ${_lt_dar_single_mod}${_lt_dar_export_syms}${_lt_dsymutil}"
    _LT_TAGVAR(module_expsym_cmds, $1)="sed -e 's,^,_,' < \$export_symbols > \$output_objdir/\${libname}-symbols.expsym~\$CC \$allow_undefined_flag -o \$lib -bundle \$libobjs \$deplibs \$compiler_flags${_lt_dar_export_syms}${_lt_dsymutil}"
    m4_if([$1], [CXX],
[   if test "$lt_cv_apple_cc_single_mod" != "yes"; then
      _LT_TAGVAR(archive_cmds, $1)="\$CC -r -keep_private_externs -nostdlib -o \${lib}-master.o \$libobjs~\$CC -dynamiclib \$allow_undefined_flag -o \$lib \${lib}-master.o \$deplibs \$compiler_flags -install_name \$rpath/\$soname \$verstring${_lt_dsymutil}"
      _LT_TAGVAR(archive_expsym_cmds, $1)="sed 's,^,_,' < \$export_symbols > \$output_objdir/\${libname}-symbols.expsym~\$CC -r -keep_private_externs -nostdlib -o \${lib}-master.o \$libobjs~\$CC -dynamiclib \$allow_undefined_flag -o \$lib \${lib}-master.o \$deplibs \$compiler_flags -install_name \$rpath/\$soname \$verstring${_lt_dar_export_syms}${_lt_dsymutil}"
    fi
],[])
  else
  _LT_TAGVAR(ld_shlibs, $1)=no
  fi
])

# _LT_SYS_MODULE_PATH_AIX
# -----------------------
# Links a minimal program and checks the executable
# for the system default hardcoded library path. In most cases,
# this is /usr/lib:/lib, but when the MPI compilers are used
# the location of the communication and MPI libs are included too.
# If we don't find anything, use the default library path according
# to the aix ld manual.
m4_defun([_LT_SYS_MODULE_PATH_AIX],
[m4_require([_LT_DECL_SED])dnl
AC_LINK_IFELSE(AC_LANG_PROGRAM,[
lt_aix_libpath_sed='
    /Import File Strings/,/^$/ {
	/^0/ {
	    s/^0  *\(.*\)$/\1/
	    p
	}
    }'
aix_libpath=`dump -H conftest$ac_exeext 2>/dev/null | $SED -n -e "$lt_aix_libpath_sed"`
# Check for a 64-bit object if we didn't find anything.
if test -z "$aix_libpath"; then
  aix_libpath=`dump -HX64 conftest$ac_exeext 2>/dev/null | $SED -n -e "$lt_aix_libpath_sed"`
fi],[])
if test -z "$aix_libpath"; then aix_libpath="/usr/lib:/lib"; fi
])# _LT_SYS_MODULE_PATH_AIX


# _LT_SHELL_INIT(ARG)
# -------------------
m4_define([_LT_SHELL_INIT],
[ifdef([AC_DIVERSION_NOTICE],
	     [AC_DIVERT_PUSH(AC_DIVERSION_NOTICE)],
	 [AC_DIVERT_PUSH(NOTICE)])
$1
AC_DIVERT_POP
])# _LT_SHELL_INIT


# _LT_PROG_ECHO_BACKSLASH
# -----------------------
# Add some code to the start of the generated configure script which
# will find an echo command which doesn't interpret backslashes.
m4_defun([_LT_PROG_ECHO_BACKSLASH],
[_LT_SHELL_INIT([
# Check that we are running under the correct shell.
SHELL=${CONFIG_SHELL-/bin/sh}

case X$lt_ECHO in
X*--fallback-echo)
  # Remove one level of quotation (which was required for Make).
  ECHO=`echo "$lt_ECHO" | sed 's,\\\\\[$]\\[$]0,'[$]0','`
  ;;
esac

ECHO=${lt_ECHO-echo}
if test "X[$]1" = X--no-reexec; then
  # Discard the --no-reexec flag, and continue.
  shift
elif test "X[$]1" = X--fallback-echo; then
  # Avoid inline document here, it may be left over
  :
elif test "X`{ $ECHO '\t'; } 2>/dev/null`" = 'X\t' ; then
  # Yippee, $ECHO works!
  :
else
  # Restart under the correct shell.
  exec $SHELL "[$]0" --no-reexec ${1+"[$]@"}
fi

if test "X[$]1" = X--fallback-echo; then
  # used as fallback echo
  shift
  cat <<_LT_EOF
[$]*
_LT_EOF
  exit 0
fi

# The HP-UX ksh and POSIX shell print the target directory to stdout
# if CDPATH is set.
(unset CDPATH) >/dev/null 2>&1 && unset CDPATH

if test -z "$lt_ECHO"; then
  if test "X${echo_test_string+set}" != Xset; then
    # find a string as large as possible, as long as the shell can cope with it
    for cmd in 'sed 50q "[$]0"' 'sed 20q "[$]0"' 'sed 10q "[$]0"' 'sed 2q "[$]0"' 'echo test'; do
      # expected sizes: less than 2Kb, 1Kb, 512 bytes, 16 bytes, ...
      if { echo_test_string=`eval $cmd`; } 2>/dev/null &&
	 { test "X$echo_test_string" = "X$echo_test_string"; } 2>/dev/null
      then
        break
      fi
    done
  fi

  if test "X`{ $ECHO '\t'; } 2>/dev/null`" = 'X\t' &&
     echo_testing_string=`{ $ECHO "$echo_test_string"; } 2>/dev/null` &&
     test "X$echo_testing_string" = "X$echo_test_string"; then
    :
  else
    # The Solaris, AIX, and Digital Unix default echo programs unquote
    # backslashes.  This makes it impossible to quote backslashes using
    #   echo "$something" | sed 's/\\/\\\\/g'
    #
    # So, first we look for a working echo in the user's PATH.

    lt_save_ifs="$IFS"; IFS=$PATH_SEPARATOR
    for dir in $PATH /usr/ucb; do
      IFS="$lt_save_ifs"
      if (test -f $dir/echo || test -f $dir/echo$ac_exeext) &&
         test "X`($dir/echo '\t') 2>/dev/null`" = 'X\t' &&
         echo_testing_string=`($dir/echo "$echo_test_string") 2>/dev/null` &&
         test "X$echo_testing_string" = "X$echo_test_string"; then
        ECHO="$dir/echo"
        break
      fi
    done
    IFS="$lt_save_ifs"

    if test "X$ECHO" = Xecho; then
      # We didn't find a better echo, so look for alternatives.
      if test "X`{ print -r '\t'; } 2>/dev/null`" = 'X\t' &&
         echo_testing_string=`{ print -r "$echo_test_string"; } 2>/dev/null` &&
         test "X$echo_testing_string" = "X$echo_test_string"; then
        # This shell has a builtin print -r that does the trick.
        ECHO='print -r'
      elif { test -f /bin/ksh || test -f /bin/ksh$ac_exeext; } &&
	   test "X$CONFIG_SHELL" != X/bin/ksh; then
        # If we have ksh, try running configure again with it.
        ORIGINAL_CONFIG_SHELL=${CONFIG_SHELL-/bin/sh}
        export ORIGINAL_CONFIG_SHELL
        CONFIG_SHELL=/bin/ksh
        export CONFIG_SHELL
        exec $CONFIG_SHELL "[$]0" --no-reexec ${1+"[$]@"}
      else
        # Try using printf.
        ECHO='printf %s\n'
        if test "X`{ $ECHO '\t'; } 2>/dev/null`" = 'X\t' &&
	   echo_testing_string=`{ $ECHO "$echo_test_string"; } 2>/dev/null` &&
	   test "X$echo_testing_string" = "X$echo_test_string"; then
	  # Cool, printf works
	  :
        elif echo_testing_string=`($ORIGINAL_CONFIG_SHELL "[$]0" --fallback-echo '\t') 2>/dev/null` &&
	     test "X$echo_testing_string" = 'X\t' &&
	     echo_testing_string=`($ORIGINAL_CONFIG_SHELL "[$]0" --fallback-echo "$echo_test_string") 2>/dev/null` &&
	     test "X$echo_testing_string" = "X$echo_test_string"; then
	  CONFIG_SHELL=$ORIGINAL_CONFIG_SHELL
	  export CONFIG_SHELL
	  SHELL="$CONFIG_SHELL"
	  export SHELL
	  ECHO="$CONFIG_SHELL [$]0 --fallback-echo"
        elif echo_testing_string=`($CONFIG_SHELL "[$]0" --fallback-echo '\t') 2>/dev/null` &&
	     test "X$echo_testing_string" = 'X\t' &&
	     echo_testing_string=`($CONFIG_SHELL "[$]0" --fallback-echo "$echo_test_string") 2>/dev/null` &&
	     test "X$echo_testing_string" = "X$echo_test_string"; then
	  ECHO="$CONFIG_SHELL [$]0 --fallback-echo"
        else
	  # maybe with a smaller string...
	  prev=:

	  for cmd in 'echo test' 'sed 2q "[$]0"' 'sed 10q "[$]0"' 'sed 20q "[$]0"' 'sed 50q "[$]0"'; do
	    if { test "X$echo_test_string" = "X`eval $cmd`"; } 2>/dev/null
	    then
	      break
	    fi
	    prev="$cmd"
	  done

	  if test "$prev" != 'sed 50q "[$]0"'; then
	    echo_test_string=`eval $prev`
	    export echo_test_string
	    exec ${ORIGINAL_CONFIG_SHELL-${CONFIG_SHELL-/bin/sh}} "[$]0" ${1+"[$]@"}
	  else
	    # Oops.  We lost completely, so just stick with echo.
	    ECHO=echo
	  fi
        fi
      fi
    fi
  fi
fi

# Copy echo and quote the copy suitably for passing to libtool from
# the Makefile, instead of quoting the original, which is used later.
lt_ECHO=$ECHO
if test "X$lt_ECHO" = "X$CONFIG_SHELL [$]0 --fallback-echo"; then
   lt_ECHO="$CONFIG_SHELL \\\$\[$]0 --fallback-echo"
fi

AC_SUBST(lt_ECHO)
])
_LT_DECL([], [SHELL], [1], [Shell to use when invoking shell scripts])
_LT_DECL([], [ECHO], [1],
    [An echo program that does not interpret backslashes])
])# _LT_PROG_ECHO_BACKSLASH


# _LT_ENABLE_LOCK
# ---------------
m4_defun([_LT_ENABLE_LOCK],
[AC_ARG_ENABLE([libtool-lock],
  [AS_HELP_STRING([--disable-libtool-lock],
    [avoid locking (might break parallel builds)])])
test "x$enable_libtool_lock" != xno && enable_libtool_lock=yes

# Some flags need to be propagated to the compiler or linker for good
# libtool support.
case $host in
ia64-*-hpux*)
  # Find out which ABI we are using.
  echo 'int i;' > conftest.$ac_ext
  if AC_TRY_EVAL(ac_compile); then
    case `/usr/bin/file conftest.$ac_objext` in
      *ELF-32*)
	HPUX_IA64_MODE="32"
	;;
      *ELF-64*)
	HPUX_IA64_MODE="64"
	;;
    esac
  fi
  rm -rf conftest*
  ;;
*-*-irix6*)
  # Find out which ABI we are using.
  echo '[#]line __oline__ "configure"' > conftest.$ac_ext
  if AC_TRY_EVAL(ac_compile); then
    if test "$lt_cv_prog_gnu_ld" = yes; then
      case `/usr/bin/file conftest.$ac_objext` in
	*32-bit*)
	  LD="${LD-ld} -melf32bsmip"
	  ;;
	*N32*)
	  LD="${LD-ld} -melf32bmipn32"
	  ;;
	*64-bit*)
	  LD="${LD-ld} -melf64bmip"
	;;
      esac
    else
      case `/usr/bin/file conftest.$ac_objext` in
	*32-bit*)
	  LD="${LD-ld} -32"
	  ;;
	*N32*)
	  LD="${LD-ld} -n32"
	  ;;
	*64-bit*)
	  LD="${LD-ld} -64"
	  ;;
      esac
    fi
  fi
  rm -rf conftest*
  ;;

x86_64-*kfreebsd*-gnu|x86_64-*linux*|ppc*-*linux*|powerpc*-*linux*| \
s390*-*linux*|s390*-*tpf*|sparc*-*linux*)
  # Find out which ABI we are using.
  echo 'int i;' > conftest.$ac_ext
  if AC_TRY_EVAL(ac_compile); then
    case `/usr/bin/file conftest.o` in
      *32-bit*)
	case $host in
	  x86_64-*kfreebsd*-gnu)
	    LD="${LD-ld} -m elf_i386_fbsd"
	    ;;
	  x86_64-*linux*)
	    LD="${LD-ld} -m elf_i386"
	    ;;
	  ppc64-*linux*|powerpc64-*linux*)
	    LD="${LD-ld} -m elf32ppclinux"
	    ;;
	  s390x-*linux*)
	    LD="${LD-ld} -m elf_s390"
	    ;;
	  sparc64-*linux*)
	    LD="${LD-ld} -m elf32_sparc"
	    ;;
	esac
	;;
      *64-bit*)
	case $host in
	  x86_64-*kfreebsd*-gnu)
	    LD="${LD-ld} -m elf_x86_64_fbsd"
	    ;;
	  x86_64-*linux*)
	    LD="${LD-ld} -m elf_x86_64"
	    ;;
	  ppc*-*linux*|powerpc*-*linux*)
	    LD="${LD-ld} -m elf64ppc"
	    ;;
	  s390*-*linux*|s390*-*tpf*)
	    LD="${LD-ld} -m elf64_s390"
	    ;;
	  sparc*-*linux*)
	    LD="${LD-ld} -m elf64_sparc"
	    ;;
	esac
	;;
    esac
  fi
  rm -rf conftest*
  ;;

*-*-sco3.2v5*)
  # On SCO OpenServer 5, we need -belf to get full-featured binaries.
  SAVE_CFLAGS="$CFLAGS"
  CFLAGS="$CFLAGS -belf"
  AC_CACHE_CHECK([whether the C compiler needs -belf], lt_cv_cc_needs_belf,
    [AC_LANG_PUSH(C)
     AC_LINK_IFELSE([AC_LANG_PROGRAM([[]],[[]])],[lt_cv_cc_needs_belf=yes],[lt_cv_cc_needs_belf=no])
     AC_LANG_POP])
  if test x"$lt_cv_cc_needs_belf" != x"yes"; then
    # this is probably gcc 2.8.0, egcs 1.0 or newer; no need for -belf
    CFLAGS="$SAVE_CFLAGS"
  fi
  ;;
sparc*-*solaris*)
  # Find out which ABI we are using.
  echo 'int i;' > conftest.$ac_ext
  if AC_TRY_EVAL(ac_compile); then
    case `/usr/bin/file conftest.o` in
    *64-bit*)
      case $lt_cv_prog_gnu_ld in
      yes*) LD="${LD-ld} -m elf64_sparc" ;;
      *)
	if ${LD-ld} -64 -r -o conftest2.o conftest.o >/dev/null 2>&1; then
	  LD="${LD-ld} -64"
	fi
	;;
      esac
      ;;
    esac
  fi
  rm -rf conftest*
  ;;
esac

need_locks="$enable_libtool_lock"
])# _LT_ENABLE_LOCK


# _LT_CMD_OLD_ARCHIVE
# -------------------
m4_defun([_LT_CMD_OLD_ARCHIVE],
[AC_CHECK_TOOL(AR, ar, false)
test -z "$AR" && AR=ar
test -z "$AR_FLAGS" && AR_FLAGS=cru
_LT_DECL([], [AR], [1], [The archiver])
_LT_DECL([], [AR_FLAGS], [1])

AC_CHECK_TOOL(STRIP, strip, :)
test -z "$STRIP" && STRIP=:
_LT_DECL([], [STRIP], [1], [A symbol stripping program])

AC_CHECK_TOOL(RANLIB, ranlib, :)
test -z "$RANLIB" && RANLIB=:
_LT_DECL([], [RANLIB], [1],
    [Commands used to install an old-style archive])

# Determine commands to create old-style static archives.
old_archive_cmds='$AR $AR_FLAGS $oldlib$oldobjs'
old_postinstall_cmds='chmod 644 $oldlib'
old_postuninstall_cmds=

if test -n "$RANLIB"; then
  case $host_os in
  openbsd*)
    old_postinstall_cmds="$old_postinstall_cmds~\$RANLIB -t \$oldlib"
    ;;
  *)
    old_postinstall_cmds="$old_postinstall_cmds~\$RANLIB \$oldlib"
    ;;
  esac
  old_archive_cmds="$old_archive_cmds~\$RANLIB \$oldlib"
fi
_LT_DECL([], [old_postinstall_cmds], [2])
_LT_DECL([], [old_postuninstall_cmds], [2])
_LT_TAGDECL([], [old_archive_cmds], [2],
    [Commands used to build an old-style archive])
])# _LT_CMD_OLD_ARCHIVE


# _LT_COMPILER_OPTION(MESSAGE, VARIABLE-NAME, FLAGS,
#		[OUTPUT-FILE], [ACTION-SUCCESS], [ACTION-FAILURE])
# ----------------------------------------------------------------
# Check whether the given compiler option works
AC_DEFUN([_LT_COMPILER_OPTION],
[m4_require([_LT_FILEUTILS_DEFAULTS])dnl
m4_require([_LT_DECL_SED])dnl
AC_CACHE_CHECK([$1], [$2],
  [$2=no
   m4_if([$4], , [ac_outfile=conftest.$ac_objext], [ac_outfile=$4])
   echo "$lt_simple_compile_test_code" > conftest.$ac_ext
   lt_compiler_flag="$3"
   # Insert the option either (1) after the last *FLAGS variable, or
   # (2) before a word containing "conftest.", or (3) at the end.
   # Note that $ac_compile itself does not contain backslashes and begins
   # with a dollar sign (not a hyphen), so the echo should work correctly.
   # The option is referenced via a variable to avoid confusing sed.
   lt_compile=`echo "$ac_compile" | $SED \
   -e 's:.*FLAGS}\{0,1\} :&$lt_compiler_flag :; t' \
   -e 's: [[^ ]]*conftest\.: $lt_compiler_flag&:; t' \
   -e 's:$: $lt_compiler_flag:'`
   (eval echo "\"\$as_me:__oline__: $lt_compile\"" >&AS_MESSAGE_LOG_FD)
   (eval "$lt_compile" 2>conftest.err)
   ac_status=$?
   cat conftest.err >&AS_MESSAGE_LOG_FD
   echo "$as_me:__oline__: \$? = $ac_status" >&AS_MESSAGE_LOG_FD
   if (exit $ac_status) && test -s "$ac_outfile"; then
     # The compiler can only warn and ignore the option if not recognized
     # So say no if there are warnings other than the usual output.
     $ECHO "X$_lt_compiler_boilerplate" | $Xsed -e '/^$/d' >conftest.exp
     $SED '/^$/d; /^ *+/d' conftest.err >conftest.er2
     if test ! -s conftest.er2 || diff conftest.exp conftest.er2 >/dev/null; then
       $2=yes
     fi
   fi
   $RM conftest*
])

if test x"[$]$2" = xyes; then
    m4_if([$5], , :, [$5])
else
    m4_if([$6], , :, [$6])
fi
])# _LT_COMPILER_OPTION

# Old name:
AU_ALIAS([AC_LIBTOOL_COMPILER_OPTION], [_LT_COMPILER_OPTION])
dnl aclocal-1.4 backwards compatibility:
dnl AC_DEFUN([AC_LIBTOOL_COMPILER_OPTION], [])


# _LT_LINKER_OPTION(MESSAGE, VARIABLE-NAME, FLAGS,
#                  [ACTION-SUCCESS], [ACTION-FAILURE])
# ----------------------------------------------------
# Check whether the given linker option works
AC_DEFUN([_LT_LINKER_OPTION],
[m4_require([_LT_FILEUTILS_DEFAULTS])dnl
m4_require([_LT_DECL_SED])dnl
AC_CACHE_CHECK([$1], [$2],
  [$2=no
   save_LDFLAGS="$LDFLAGS"
   LDFLAGS="$LDFLAGS $3"
   echo "$lt_simple_link_test_code" > conftest.$ac_ext
   if (eval $ac_link 2>conftest.err) && test -s conftest$ac_exeext; then
     # The linker can only warn and ignore the option if not recognized
     # So say no if there are warnings
     if test -s conftest.err; then
       # Append any errors to the config.log.
       cat conftest.err 1>&AS_MESSAGE_LOG_FD
       $ECHO "X$_lt_linker_boilerplate" | $Xsed -e '/^$/d' > conftest.exp
       $SED '/^$/d; /^ *+/d' conftest.err >conftest.er2
       if diff conftest.exp conftest.er2 >/dev/null; then
         $2=yes
       fi
     else
       $2=yes
     fi
   fi
   $RM -r conftest*
   LDFLAGS="$save_LDFLAGS"
])

if test x"[$]$2" = xyes; then
    m4_if([$4], , :, [$4])
else
    m4_if([$5], , :, [$5])
fi
])# _LT_LINKER_OPTION

# Old name:
AU_ALIAS([AC_LIBTOOL_LINKER_OPTION], [_LT_LINKER_OPTION])
dnl aclocal-1.4 backwards compatibility:
dnl AC_DEFUN([AC_LIBTOOL_LINKER_OPTION], [])


# LT_CMD_MAX_LEN
#---------------
AC_DEFUN([LT_CMD_MAX_LEN],
[AC_REQUIRE([AC_CANONICAL_HOST])dnl
# find the maximum length of command line arguments
AC_MSG_CHECKING([the maximum length of command line arguments])
AC_CACHE_VAL([lt_cv_sys_max_cmd_len], [dnl
  i=0
  teststring="ABCD"

  case $build_os in
  msdosdjgpp*)
    # On DJGPP, this test can blow up pretty badly due to problems in libc
    # (any single argument exceeding 2000 bytes causes a buffer overrun
    # during glob expansion).  Even if it were fixed, the result of this
    # check would be larger than it should be.
    lt_cv_sys_max_cmd_len=12288;    # 12K is about right
    ;;

  gnu*)
    # Under GNU Hurd, this test is not required because there is
    # no limit to the length of command line arguments.
    # Libtool will interpret -1 as no limit whatsoever
    lt_cv_sys_max_cmd_len=-1;
    ;;

  cygwin* | mingw* | cegcc*)
    # On Win9x/ME, this test blows up -- it succeeds, but takes
    # about 5 minutes as the teststring grows exponentially.
    # Worse, since 9x/ME are not pre-emptively multitasking,
    # you end up with a "frozen" computer, even though with patience
    # the test eventually succeeds (with a max line length of 256k).
    # Instead, let's just punt: use the minimum linelength reported by
    # all of the supported platforms: 8192 (on NT/2K/XP).
    lt_cv_sys_max_cmd_len=8192;
    ;;

  amigaos*)
    # On AmigaOS with pdksh, this test takes hours, literally.
    # So we just punt and use a minimum line length of 8192.
    lt_cv_sys_max_cmd_len=8192;
    ;;

  netbsd* | freebsd* | openbsd* | darwin* | dragonfly*)
    # This has been around since 386BSD, at least.  Likely further.
    if test -x /sbin/sysctl; then
      lt_cv_sys_max_cmd_len=`/sbin/sysctl -n kern.argmax`
    elif test -x /usr/sbin/sysctl; then
      lt_cv_sys_max_cmd_len=`/usr/sbin/sysctl -n kern.argmax`
    else
      lt_cv_sys_max_cmd_len=65536	# usable default for all BSDs
    fi
    # And add a safety zone
    lt_cv_sys_max_cmd_len=`expr $lt_cv_sys_max_cmd_len \/ 4`
    lt_cv_sys_max_cmd_len=`expr $lt_cv_sys_max_cmd_len \* 3`
    ;;

  interix*)
    # We know the value 262144 and hardcode it with a safety zone (like BSD)
    lt_cv_sys_max_cmd_len=196608
    ;;

  osf*)
    # Dr. Hans Ekkehard Plesser reports seeing a kernel panic running configure
    # due to this test when exec_disable_arg_limit is 1 on Tru64. It is not
    # nice to cause kernel panics so lets avoid the loop below.
    # First set a reasonable default.
    lt_cv_sys_max_cmd_len=16384
    #
    if test -x /sbin/sysconfig; then
      case `/sbin/sysconfig -q proc exec_disable_arg_limit` in
        *1*) lt_cv_sys_max_cmd_len=-1 ;;
      esac
    fi
    ;;
  sco3.2v5*)
    lt_cv_sys_max_cmd_len=102400
    ;;
  sysv5* | sco5v6* | sysv4.2uw2*)
    kargmax=`grep ARG_MAX /etc/conf/cf.d/stune 2>/dev/null`
    if test -n "$kargmax"; then
      lt_cv_sys_max_cmd_len=`echo $kargmax | sed 's/.*[[	 ]]//'`
    else
      lt_cv_sys_max_cmd_len=32768
    fi
    ;;
  *)
    lt_cv_sys_max_cmd_len=`(getconf ARG_MAX) 2> /dev/null`
    if test -n "$lt_cv_sys_max_cmd_len"; then
      lt_cv_sys_max_cmd_len=`expr $lt_cv_sys_max_cmd_len \/ 4`
      lt_cv_sys_max_cmd_len=`expr $lt_cv_sys_max_cmd_len \* 3`
    else
      # Make teststring a little bigger before we do anything with it.
      # a 1K string should be a reasonable start.
      for i in 1 2 3 4 5 6 7 8 ; do
        teststring=$teststring$teststring
      done
      SHELL=${SHELL-${CONFIG_SHELL-/bin/sh}}
      # If test is not a shell built-in, we'll probably end up computing a
      # maximum length that is only half of the actual maximum length, but
      # we can't tell.
      while { test "X"`$SHELL [$]0 --fallback-echo "X$teststring$teststring" 2>/dev/null` \
	         = "XX$teststring$teststring"; } >/dev/null 2>&1 &&
	      test $i != 17 # 1/2 MB should be enough
      do
        i=`expr $i + 1`
        teststring=$teststring$teststring
      done
      # Only check the string length outside the loop.
      lt_cv_sys_max_cmd_len=`expr "X$teststring" : ".*" 2>&1`
      teststring=
      # Add a significant safety factor because C++ compilers can tack on
      # massive amounts of additional arguments before passing them to the
      # linker.  It appears as though 1/2 is a usable value.
      lt_cv_sys_max_cmd_len=`expr $lt_cv_sys_max_cmd_len \/ 2`
    fi
    ;;
  esac
])
if test -n $lt_cv_sys_max_cmd_len ; then
  AC_MSG_RESULT($lt_cv_sys_max_cmd_len)
else
  AC_MSG_RESULT(none)
fi
max_cmd_len=$lt_cv_sys_max_cmd_len
_LT_DECL([], [max_cmd_len], [0],
    [What is the maximum length of a command?])
])# LT_CMD_MAX_LEN

# Old name:
AU_ALIAS([AC_LIBTOOL_SYS_MAX_CMD_LEN], [LT_CMD_MAX_LEN])
dnl aclocal-1.4 backwards compatibility:
dnl AC_DEFUN([AC_LIBTOOL_SYS_MAX_CMD_LEN], [])


# _LT_HEADER_DLFCN
# ----------------
m4_defun([_LT_HEADER_DLFCN],
[AC_CHECK_HEADERS([dlfcn.h], [], [], [AC_INCLUDES_DEFAULT])dnl
])# _LT_HEADER_DLFCN


# _LT_TRY_DLOPEN_SELF (ACTION-IF-TRUE, ACTION-IF-TRUE-W-USCORE,
#                      ACTION-IF-FALSE, ACTION-IF-CROSS-COMPILING)
# ----------------------------------------------------------------
m4_defun([_LT_TRY_DLOPEN_SELF],
[m4_require([_LT_HEADER_DLFCN])dnl
if test "$cross_compiling" = yes; then :
  [$4]
else
  lt_dlunknown=0; lt_dlno_uscore=1; lt_dlneed_uscore=2
  lt_status=$lt_dlunknown
  cat > conftest.$ac_ext <<_LT_EOF
[#line __oline__ "configure"
#include "confdefs.h"

#if HAVE_DLFCN_H
#include <dlfcn.h>
#endif

#include <stdio.h>

#ifdef RTLD_GLOBAL
#  define LT_DLGLOBAL		RTLD_GLOBAL
#else
#  ifdef DL_GLOBAL
#    define LT_DLGLOBAL		DL_GLOBAL
#  else
#    define LT_DLGLOBAL		0
#  endif
#endif

/* We may have to define LT_DLLAZY_OR_NOW in the command line if we
   find out it does not work in some platform. */
#ifndef LT_DLLAZY_OR_NOW
#  ifdef RTLD_LAZY
#    define LT_DLLAZY_OR_NOW		RTLD_LAZY
#  else
#    ifdef DL_LAZY
#      define LT_DLLAZY_OR_NOW		DL_LAZY
#    else
#      ifdef RTLD_NOW
#        define LT_DLLAZY_OR_NOW	RTLD_NOW
#      else
#        ifdef DL_NOW
#          define LT_DLLAZY_OR_NOW	DL_NOW
#        else
#          define LT_DLLAZY_OR_NOW	0
#        endif
#      endif
#    endif
#  endif
#endif

void fnord() { int i=42;}
int main ()
{
  void *self = dlopen (0, LT_DLGLOBAL|LT_DLLAZY_OR_NOW);
  int status = $lt_dlunknown;

  if (self)
    {
      if (dlsym (self,"fnord"))       status = $lt_dlno_uscore;
      else if (dlsym( self,"_fnord")) status = $lt_dlneed_uscore;
      /* dlclose (self); */
    }
  else
    puts (dlerror ());

  return status;
}]
_LT_EOF
  if AC_TRY_EVAL(ac_link) && test -s conftest${ac_exeext} 2>/dev/null; then
    (./conftest; exit; ) >&AS_MESSAGE_LOG_FD 2>/dev/null
    lt_status=$?
    case x$lt_status in
      x$lt_dlno_uscore) $1 ;;
      x$lt_dlneed_uscore) $2 ;;
      x$lt_dlunknown|x*) $3 ;;
    esac
  else :
    # compilation failed
    $3
  fi
fi
rm -fr conftest*
])# _LT_TRY_DLOPEN_SELF


# LT_SYS_DLOPEN_SELF
# ------------------
AC_DEFUN([LT_SYS_DLOPEN_SELF],
[m4_require([_LT_HEADER_DLFCN])dnl
if test "x$enable_dlopen" != xyes; then
  enable_dlopen=unknown
  enable_dlopen_self=unknown
  enable_dlopen_self_static=unknown
else
  lt_cv_dlopen=no
  lt_cv_dlopen_libs=

  case $host_os in
  beos*)
    lt_cv_dlopen="load_add_on"
    lt_cv_dlopen_libs=
    lt_cv_dlopen_self=yes
    ;;

  mingw* | pw32* | cegcc*)
    lt_cv_dlopen="LoadLibrary"
    lt_cv_dlopen_libs=
    ;;

  cygwin*)
    lt_cv_dlopen="dlopen"
    lt_cv_dlopen_libs=
    ;;

  darwin*)
  # if libdl is installed we need to link against it
    AC_CHECK_LIB([dl], [dlopen],
		[lt_cv_dlopen="dlopen" lt_cv_dlopen_libs="-ldl"],[
    lt_cv_dlopen="dyld"
    lt_cv_dlopen_libs=
    lt_cv_dlopen_self=yes
    ])
    ;;

  *)
    AC_CHECK_FUNC([shl_load],
	  [lt_cv_dlopen="shl_load"],
      [AC_CHECK_LIB([dld], [shl_load],
	    [lt_cv_dlopen="shl_load" lt_cv_dlopen_libs="-ldld"],
	[AC_CHECK_FUNC([dlopen],
	      [lt_cv_dlopen="dlopen"],
	  [AC_CHECK_LIB([dl], [dlopen],
		[lt_cv_dlopen="dlopen" lt_cv_dlopen_libs="-ldl"],
	    [AC_CHECK_LIB([svld], [dlopen],
		  [lt_cv_dlopen="dlopen" lt_cv_dlopen_libs="-lsvld"],
	      [AC_CHECK_LIB([dld], [dld_link],
		    [lt_cv_dlopen="dld_link" lt_cv_dlopen_libs="-ldld"])
	      ])
	    ])
	  ])
	])
      ])
    ;;
  esac

  if test "x$lt_cv_dlopen" != xno; then
    enable_dlopen=yes
  else
    enable_dlopen=no
  fi

  case $lt_cv_dlopen in
  dlopen)
    save_CPPFLAGS="$CPPFLAGS"
    test "x$ac_cv_header_dlfcn_h" = xyes && CPPFLAGS="$CPPFLAGS -DHAVE_DLFCN_H"

    save_LDFLAGS="$LDFLAGS"
    wl=$lt_prog_compiler_wl eval LDFLAGS=\"\$LDFLAGS $export_dynamic_flag_spec\"

    save_LIBS="$LIBS"
    LIBS="$lt_cv_dlopen_libs $LIBS"

    AC_CACHE_CHECK([whether a program can dlopen itself],
	  lt_cv_dlopen_self, [dnl
	  _LT_TRY_DLOPEN_SELF(
	    lt_cv_dlopen_self=yes, lt_cv_dlopen_self=yes,
	    lt_cv_dlopen_self=no, lt_cv_dlopen_self=cross)
    ])

    if test "x$lt_cv_dlopen_self" = xyes; then
      wl=$lt_prog_compiler_wl eval LDFLAGS=\"\$LDFLAGS $lt_prog_compiler_static\"
      AC_CACHE_CHECK([whether a statically linked program can dlopen itself],
	  lt_cv_dlopen_self_static, [dnl
	  _LT_TRY_DLOPEN_SELF(
	    lt_cv_dlopen_self_static=yes, lt_cv_dlopen_self_static=yes,
	    lt_cv_dlopen_self_static=no,  lt_cv_dlopen_self_static=cross)
      ])
    fi

    CPPFLAGS="$save_CPPFLAGS"
    LDFLAGS="$save_LDFLAGS"
    LIBS="$save_LIBS"
    ;;
  esac

  case $lt_cv_dlopen_self in
  yes|no) enable_dlopen_self=$lt_cv_dlopen_self ;;
  *) enable_dlopen_self=unknown ;;
  esac

  case $lt_cv_dlopen_self_static in
  yes|no) enable_dlopen_self_static=$lt_cv_dlopen_self_static ;;
  *) enable_dlopen_self_static=unknown ;;
  esac
fi
_LT_DECL([dlopen_support], [enable_dlopen], [0],
	 [Whether dlopen is supported])
_LT_DECL([dlopen_self], [enable_dlopen_self], [0],
	 [Whether dlopen of programs is supported])
_LT_DECL([dlopen_self_static], [enable_dlopen_self_static], [0],
	 [Whether dlopen of statically linked programs is supported])
])# LT_SYS_DLOPEN_SELF

# Old name:
AU_ALIAS([AC_LIBTOOL_DLOPEN_SELF], [LT_SYS_DLOPEN_SELF])
dnl aclocal-1.4 backwards compatibility:
dnl AC_DEFUN([AC_LIBTOOL_DLOPEN_SELF], [])


# _LT_COMPILER_C_O([TAGNAME])
# ---------------------------
# Check to see if options -c and -o are simultaneously supported by compiler.
# This macro does not hard code the compiler like AC_PROG_CC_C_O.
m4_defun([_LT_COMPILER_C_O],
[m4_require([_LT_DECL_SED])dnl
m4_require([_LT_FILEUTILS_DEFAULTS])dnl
m4_require([_LT_TAG_COMPILER])dnl
AC_CACHE_CHECK([if $compiler supports -c -o file.$ac_objext],
  [_LT_TAGVAR(lt_cv_prog_compiler_c_o, $1)],
  [_LT_TAGVAR(lt_cv_prog_compiler_c_o, $1)=no
   $RM -r conftest 2>/dev/null
   mkdir conftest
   cd conftest
   mkdir out
   echo "$lt_simple_compile_test_code" > conftest.$ac_ext

   lt_compiler_flag="-o out/conftest2.$ac_objext"
   # Insert the option either (1) after the last *FLAGS variable, or
   # (2) before a word containing "conftest.", or (3) at the end.
   # Note that $ac_compile itself does not contain backslashes and begins
   # with a dollar sign (not a hyphen), so the echo should work correctly.
   lt_compile=`echo "$ac_compile" | $SED \
   -e 's:.*FLAGS}\{0,1\} :&$lt_compiler_flag :; t' \
   -e 's: [[^ ]]*conftest\.: $lt_compiler_flag&:; t' \
   -e 's:$: $lt_compiler_flag:'`
   (eval echo "\"\$as_me:__oline__: $lt_compile\"" >&AS_MESSAGE_LOG_FD)
   (eval "$lt_compile" 2>out/conftest.err)
   ac_status=$?
   cat out/conftest.err >&AS_MESSAGE_LOG_FD
   echo "$as_me:__oline__: \$? = $ac_status" >&AS_MESSAGE_LOG_FD
   if (exit $ac_status) && test -s out/conftest2.$ac_objext
   then
     # The compiler can only warn and ignore the option if not recognized
     # So say no if there are warnings
     $ECHO "X$_lt_compiler_boilerplate" | $Xsed -e '/^$/d' > out/conftest.exp
     $SED '/^$/d; /^ *+/d' out/conftest.err >out/conftest.er2
     if test ! -s out/conftest.er2 || diff out/conftest.exp out/conftest.er2 >/dev/null; then
       _LT_TAGVAR(lt_cv_prog_compiler_c_o, $1)=yes
     fi
   fi
   chmod u+w . 2>&AS_MESSAGE_LOG_FD
   $RM conftest*
   # SGI C++ compiler will create directory out/ii_files/ for
   # template instantiation
   test -d out/ii_files && $RM out/ii_files/* && rmdir out/ii_files
   $RM out/* && rmdir out
   cd ..
   $RM -r conftest
   $RM conftest*
])
_LT_TAGDECL([compiler_c_o], [lt_cv_prog_compiler_c_o], [1],
	[Does compiler simultaneously support -c and -o options?])
])# _LT_COMPILER_C_O


# _LT_COMPILER_FILE_LOCKS([TAGNAME])
# ----------------------------------
# Check to see if we can do hard links to lock some files if needed
m4_defun([_LT_COMPILER_FILE_LOCKS],
[m4_require([_LT_ENABLE_LOCK])dnl
m4_require([_LT_FILEUTILS_DEFAULTS])dnl
_LT_COMPILER_C_O([$1])

hard_links="nottested"
if test "$_LT_TAGVAR(lt_cv_prog_compiler_c_o, $1)" = no && test "$need_locks" != no; then
  # do not overwrite the value of need_locks provided by the user
  AC_MSG_CHECKING([if we can lock with hard links])
  hard_links=yes
  $RM conftest*
  ln conftest.a conftest.b 2>/dev/null && hard_links=no
  touch conftest.a
  ln conftest.a conftest.b 2>&5 || hard_links=no
  ln conftest.a conftest.b 2>/dev/null && hard_links=no
  AC_MSG_RESULT([$hard_links])
  if test "$hard_links" = no; then
    AC_MSG_WARN([`$CC' does not support `-c -o', so `make -j' may be unsafe])
    need_locks=warn
  fi
else
  need_locks=no
fi
_LT_DECL([], [need_locks], [1], [Must we lock files when doing compilation?])
])# _LT_COMPILER_FILE_LOCKS


# _LT_CHECK_OBJDIR
# ----------------
m4_defun([_LT_CHECK_OBJDIR],
[AC_CACHE_CHECK([for objdir], [lt_cv_objdir],
[rm -f .libs 2>/dev/null
mkdir .libs 2>/dev/null
if test -d .libs; then
  lt_cv_objdir=.libs
else
  # MS-DOS does not allow filenames that begin with a dot.
  lt_cv_objdir=_libs
fi
rmdir .libs 2>/dev/null])
objdir=$lt_cv_objdir
_LT_DECL([], [objdir], [0],
         [The name of the directory that contains temporary libtool files])dnl
m4_pattern_allow([LT_OBJDIR])dnl
AC_DEFINE_UNQUOTED(LT_OBJDIR, "$lt_cv_objdir/",
  [Define to the sub-directory in which libtool stores uninstalled libraries.])
])# _LT_CHECK_OBJDIR


# _LT_LINKER_HARDCODE_LIBPATH([TAGNAME])
# --------------------------------------
# Check hardcoding attributes.
m4_defun([_LT_LINKER_HARDCODE_LIBPATH],
[AC_MSG_CHECKING([how to hardcode library paths into programs])
_LT_TAGVAR(hardcode_action, $1)=
if test -n "$_LT_TAGVAR(hardcode_libdir_flag_spec, $1)" ||
   test -n "$_LT_TAGVAR(runpath_var, $1)" ||
   test "X$_LT_TAGVAR(hardcode_automatic, $1)" = "Xyes" ; then

  # We can hardcode non-existent directories.
  if test "$_LT_TAGVAR(hardcode_direct, $1)" != no &&
     # If the only mechanism to avoid hardcoding is shlibpath_var, we
     # have to relink, otherwise we might link with an installed library
     # when we should be linking with a yet-to-be-installed one
     ## test "$_LT_TAGVAR(hardcode_shlibpath_var, $1)" != no &&
     test "$_LT_TAGVAR(hardcode_minus_L, $1)" != no; then
    # Linking always hardcodes the temporary library directory.
    _LT_TAGVAR(hardcode_action, $1)=relink
  else
    # We can link without hardcoding, and we can hardcode nonexisting dirs.
    _LT_TAGVAR(hardcode_action, $1)=immediate
  fi
else
  # We cannot hardcode anything, or else we can only hardcode existing
  # directories.
  _LT_TAGVAR(hardcode_action, $1)=unsupported
fi
AC_MSG_RESULT([$_LT_TAGVAR(hardcode_action, $1)])

if test "$_LT_TAGVAR(hardcode_action, $1)" = relink ||
   test "$_LT_TAGVAR(inherit_rpath, $1)" = yes; then
  # Fast installation is not supported
  enable_fast_install=no
elif test "$shlibpath_overrides_runpath" = yes ||
     test "$enable_shared" = no; then
  # Fast installation is not necessary
  enable_fast_install=needless
fi
_LT_TAGDECL([], [hardcode_action], [0],
    [How to hardcode a shared library path into an executable])
])# _LT_LINKER_HARDCODE_LIBPATH


# _LT_CMD_STRIPLIB
# ----------------
m4_defun([_LT_CMD_STRIPLIB],
[m4_require([_LT_DECL_EGREP])
striplib=
old_striplib=
AC_MSG_CHECKING([whether stripping libraries is possible])
if test -n "$STRIP" && $STRIP -V 2>&1 | $GREP "GNU strip" >/dev/null; then
  test -z "$old_striplib" && old_striplib="$STRIP --strip-debug"
  test -z "$striplib" && striplib="$STRIP --strip-unneeded"
  AC_MSG_RESULT([yes])
else
# FIXME - insert some real tests, host_os isn't really good enough
  case $host_os in
  darwin*)
    if test -n "$STRIP" ; then
      striplib="$STRIP -x"
      old_striplib="$STRIP -S"
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
    fi
    ;;
  *)
    AC_MSG_RESULT([no])
    ;;
  esac
fi
_LT_DECL([], [old_striplib], [1], [Commands to strip libraries])
_LT_DECL([], [striplib], [1])
])# _LT_CMD_STRIPLIB


# _LT_SYS_DYNAMIC_LINKER([TAG])
# -----------------------------
# PORTME Fill in your ld.so characteristics
m4_defun([_LT_SYS_DYNAMIC_LINKER],
[AC_REQUIRE([AC_CANONICAL_HOST])dnl
m4_require([_LT_DECL_EGREP])dnl
m4_require([_LT_FILEUTILS_DEFAULTS])dnl
m4_require([_LT_DECL_OBJDUMP])dnl
m4_require([_LT_DECL_SED])dnl
AC_MSG_CHECKING([dynamic linker characteristics])
m4_if([$1],
	[], [
if test "$GCC" = yes; then
  case $host_os in
    darwin*) lt_awk_arg="/^libraries:/,/LR/" ;;
    *) lt_awk_arg="/^libraries:/" ;;
  esac
  lt_search_path_spec=`$CC -print-search-dirs | awk $lt_awk_arg | $SED -e "s/^libraries://" -e "s,=/,/,g"`
  if $ECHO "$lt_search_path_spec" | $GREP ';' >/dev/null ; then
    # if the path contains ";" then we assume it to be the separator
    # otherwise default to the standard path separator (i.e. ":") - it is
    # assumed that no part of a normal pathname contains ";" but that should
    # okay in the real world where ";" in dirpaths is itself problematic.
    lt_search_path_spec=`$ECHO "$lt_search_path_spec" | $SED -e 's/;/ /g'`
  else
    lt_search_path_spec=`$ECHO "$lt_search_path_spec" | $SED  -e "s/$PATH_SEPARATOR/ /g"`
  fi
  # Ok, now we have the path, separated by spaces, we can step through it
  # and add multilib dir if necessary.
  lt_tmp_lt_search_path_spec=
  lt_multi_os_dir=`$CC $CPPFLAGS $CFLAGS $LDFLAGS -print-multi-os-directory 2>/dev/null`
  for lt_sys_path in $lt_search_path_spec; do
    if test -d "$lt_sys_path/$lt_multi_os_dir"; then
      lt_tmp_lt_search_path_spec="$lt_tmp_lt_search_path_spec $lt_sys_path/$lt_multi_os_dir"
    else
      test -d "$lt_sys_path" && \
	lt_tmp_lt_search_path_spec="$lt_tmp_lt_search_path_spec $lt_sys_path"
    fi
  done
  lt_search_path_spec=`$ECHO $lt_tmp_lt_search_path_spec | awk '
BEGIN {RS=" "; FS="/|\n";} {
  lt_foo="";
  lt_count=0;
  for (lt_i = NF; lt_i > 0; lt_i--) {
    if ($lt_i != "" && $lt_i != ".") {
      if ($lt_i == "..") {
        lt_count++;
      } else {
        if (lt_count == 0) {
          lt_foo="/" $lt_i lt_foo;
        } else {
          lt_count--;
        }
      }
    }
  }
  if (lt_foo != "") { lt_freq[[lt_foo]]++; }
  if (lt_freq[[lt_foo]] == 1) { print lt_foo; }
}'`
  sys_lib_search_path_spec=`$ECHO $lt_search_path_spec`
else
  sys_lib_search_path_spec="/lib /usr/lib /usr/local/lib"
fi])
library_names_spec=
libname_spec='lib$name'
soname_spec=
shrext_cmds=".so"
postinstall_cmds=
postuninstall_cmds=
finish_cmds=
finish_eval=
shlibpath_var=
shlibpath_overrides_runpath=unknown
version_type=none
dynamic_linker="$host_os ld.so"
sys_lib_dlsearch_path_spec="/lib /usr/lib"
need_lib_prefix=unknown
hardcode_into_libs=no

# when you set need_version to no, make sure it does not cause -set_version
# flags to be left without arguments
need_version=unknown

case $host_os in
aix3*)
  version_type=linux
  library_names_spec='${libname}${release}${shared_ext}$versuffix $libname.a'
  shlibpath_var=LIBPATH

  # AIX 3 has no versioning support, so we append a major version to the name.
  soname_spec='${libname}${release}${shared_ext}$major'
  ;;

aix[[4-9]]*)
  version_type=linux
  need_lib_prefix=no
  need_version=no
  hardcode_into_libs=yes
  if test "$host_cpu" = ia64; then
    # AIX 5 supports IA64
    library_names_spec='${libname}${release}${shared_ext}$major ${libname}${release}${shared_ext}$versuffix $libname${shared_ext}'
    shlibpath_var=LD_LIBRARY_PATH
  else
    # With GCC up to 2.95.x, collect2 would create an import file
    # for dependence libraries.  The import file would start with
    # the line `#! .'.  This would cause the generated library to
    # depend on `.', always an invalid library.  This was fixed in
    # development snapshots of GCC prior to 3.0.
    case $host_os in
      aix4 | aix4.[[01]] | aix4.[[01]].*)
      if { echo '#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 97)'
	   echo ' yes '
	   echo '#endif'; } | ${CC} -E - | $GREP yes > /dev/null; then
	:
      else
	can_build_shared=no
      fi
      ;;
    esac
    # AIX (on Power*) has no versioning support, so currently we can not hardcode correct
    # soname into executable. Probably we can add versioning support to
    # collect2, so additional links can be useful in future.
    if test "$aix_use_runtimelinking" = yes; then
      # If using run time linking (on AIX 4.2 or later) use lib<name>.so
      # instead of lib<name>.a to let people know that these are not
      # typical AIX shared libraries.
      library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext}$major $libname${shared_ext}'
    else
      # We preserve .a as extension for shared libraries through AIX4.2
      # and later when we are not doing run time linking.
      library_names_spec='${libname}${release}.a $libname.a'
      soname_spec='${libname}${release}${shared_ext}$major'
    fi
    shlibpath_var=LIBPATH
  fi
  ;;

amigaos*)
  case $host_cpu in
  powerpc)
    # Since July 2007 AmigaOS4 officially supports .so libraries.
    # When compiling the executable, add -use-dynld -Lsobjs: to the compileline.
    library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext}$major $libname${shared_ext}'
    ;;
  m68k)
    library_names_spec='$libname.ixlibrary $libname.a'
    # Create ${libname}_ixlibrary.a entries in /sys/libs.
    finish_eval='for lib in `ls $libdir/*.ixlibrary 2>/dev/null`; do libname=`$ECHO "X$lib" | $Xsed -e '\''s%^.*/\([[^/]]*\)\.ixlibrary$%\1%'\''`; test $RM /sys/libs/${libname}_ixlibrary.a; $show "cd /sys/libs && $LN_S $lib ${libname}_ixlibrary.a"; cd /sys/libs && $LN_S $lib ${libname}_ixlibrary.a || exit 1; done'
    ;;
  esac
  ;;

beos*)
  library_names_spec='${libname}${shared_ext}'
  dynamic_linker="$host_os ld.so"
  shlibpath_var=LIBRARY_PATH
  ;;

bsdi[[45]]*)
  version_type=linux
  need_version=no
  library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext}$major $libname${shared_ext}'
  soname_spec='${libname}${release}${shared_ext}$major'
  finish_cmds='PATH="\$PATH:/sbin" ldconfig $libdir'
  shlibpath_var=LD_LIBRARY_PATH
  sys_lib_search_path_spec="/shlib /usr/lib /usr/X11/lib /usr/contrib/lib /lib /usr/local/lib"
  sys_lib_dlsearch_path_spec="/shlib /usr/lib /usr/local/lib"
  # the default ld.so.conf also contains /usr/contrib/lib and
  # /usr/X11R6/lib (/usr/X11 is a link to /usr/X11R6), but let us allow
  # libtool to hard-code these into programs
  ;;

cygwin* | mingw* | pw32* | cegcc*)
  version_type=windows
  shrext_cmds=".dll"
  need_version=no
  need_lib_prefix=no

  case $GCC,$host_os in
  yes,cygwin* | yes,mingw* | yes,pw32* | yes,cegcc*)
    library_names_spec='$libname.dll.a'
    # DLL is installed to $(libdir)/../bin by postinstall_cmds
    postinstall_cmds='base_file=`basename \${file}`~
      dlpath=`$SHELL 2>&1 -c '\''. $dir/'\''\${base_file}'\''i; echo \$dlname'\''`~
      dldir=$destdir/`dirname \$dlpath`~
      test -d \$dldir || mkdir -p \$dldir~
      $install_prog $dir/$dlname \$dldir/$dlname~
      chmod a+x \$dldir/$dlname~
      if test -n '\''$stripme'\'' && test -n '\''$striplib'\''; then
        eval '\''$striplib \$dldir/$dlname'\'' || exit \$?;
      fi'
    postuninstall_cmds='dldll=`$SHELL 2>&1 -c '\''. $file; echo \$dlname'\''`~
      dlpath=$dir/\$dldll~
       $RM \$dlpath'
    shlibpath_overrides_runpath=yes

    case $host_os in
    cygwin*)
      # Cygwin DLLs use 'cyg' prefix rather than 'lib'
      soname_spec='`echo ${libname} | sed -e 's/^lib/cyg/'``echo ${release} | $SED -e 's/[[.]]/-/g'`${versuffix}${shared_ext}'
      sys_lib_search_path_spec="/usr/lib /lib/w32api /lib /usr/local/lib"
      ;;
    mingw* | cegcc*)
      # MinGW DLLs use traditional 'lib' prefix
      soname_spec='${libname}`echo ${release} | $SED -e 's/[[.]]/-/g'`${versuffix}${shared_ext}'
      sys_lib_search_path_spec=`$CC -print-search-dirs | $GREP "^libraries:" | $SED -e "s/^libraries://" -e "s,=/,/,g"`
      if $ECHO "$sys_lib_search_path_spec" | [$GREP ';[c-zC-Z]:/' >/dev/null]; then
        # It is most probably a Windows format PATH printed by
        # mingw gcc, but we are running on Cygwin. Gcc prints its search
        # path with ; separators, and with drive letters. We can handle the
        # drive letters (cygwin fileutils understands them), so leave them,
        # especially as we might pass files found there to a mingw objdump,
        # which wouldn't understand a cygwinified path. Ahh.
        sys_lib_search_path_spec=`$ECHO "$sys_lib_search_path_spec" | $SED -e 's/;/ /g'`
      else
        sys_lib_search_path_spec=`$ECHO "$sys_lib_search_path_spec" | $SED  -e "s/$PATH_SEPARATOR/ /g"`
      fi
      ;;
    pw32*)
      # pw32 DLLs use 'pw' prefix rather than 'lib'
      library_names_spec='`echo ${libname} | sed -e 's/^lib/pw/'``echo ${release} | $SED -e 's/[[.]]/-/g'`${versuffix}${shared_ext}'
      ;;
    esac
    ;;

  *)
    library_names_spec='${libname}`echo ${release} | $SED -e 's/[[.]]/-/g'`${versuffix}${shared_ext} $libname.lib'
    ;;
  esac
  dynamic_linker='Win32 ld.exe'
  # FIXME: first we should search . and the directory the executable is in
  shlibpath_var=PATH
  ;;

darwin* | rhapsody*)
  dynamic_linker="$host_os dyld"
  version_type=darwin
  need_lib_prefix=no
  need_version=no
  library_names_spec='${libname}${release}${major}$shared_ext ${libname}$shared_ext'
  soname_spec='${libname}${release}${major}$shared_ext'
  shlibpath_overrides_runpath=yes
  shlibpath_var=DYLD_LIBRARY_PATH
  shrext_cmds='`test .$module = .yes && echo .so || echo .dylib`'
m4_if([$1], [],[
  sys_lib_search_path_spec="$sys_lib_search_path_spec /usr/local/lib"])
  sys_lib_dlsearch_path_spec='/usr/local/lib /lib /usr/lib'
  ;;

dgux*)
  version_type=linux
  need_lib_prefix=no
  need_version=no
  library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext}$major $libname$shared_ext'
  soname_spec='${libname}${release}${shared_ext}$major'
  shlibpath_var=LD_LIBRARY_PATH
  ;;

freebsd1*)
  dynamic_linker=no
  ;;

freebsd* | dragonfly*)
  # DragonFly does not have aout.  When/if they implement a new
  # versioning mechanism, adjust this.
  if test -x /usr/bin/objformat; then
    objformat=`/usr/bin/objformat`
  else
    case $host_os in
    freebsd[[123]]*) objformat=aout ;;
    *) objformat=elf ;;
    esac
  fi
  version_type=freebsd-$objformat
  case $version_type in
    freebsd-elf*)
      library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext} $libname${shared_ext}'
      need_version=no
      need_lib_prefix=no
      ;;
    freebsd-*)
      library_names_spec='${libname}${release}${shared_ext}$versuffix $libname${shared_ext}$versuffix'
      need_version=yes
      ;;
  esac
  shlibpath_var=LD_LIBRARY_PATH
  case $host_os in
  freebsd2*)
    shlibpath_overrides_runpath=yes
    ;;
  freebsd3.[[01]]* | freebsdelf3.[[01]]*)
    shlibpath_overrides_runpath=yes
    hardcode_into_libs=yes
    ;;
  freebsd3.[[2-9]]* | freebsdelf3.[[2-9]]* | \
  freebsd4.[[0-5]] | freebsdelf4.[[0-5]] | freebsd4.1.1 | freebsdelf4.1.1)
    shlibpath_overrides_runpath=no
    hardcode_into_libs=yes
    ;;
  *) # from 4.6 on, and DragonFly
    shlibpath_overrides_runpath=yes
    hardcode_into_libs=yes
    ;;
  esac
  ;;

gnu*)
  version_type=linux
  need_lib_prefix=no
  need_version=no
  library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext}${major} ${libname}${shared_ext}'
  soname_spec='${libname}${release}${shared_ext}$major'
  shlibpath_var=LD_LIBRARY_PATH
  hardcode_into_libs=yes
  ;;

hpux9* | hpux10* | hpux11*)
  # Give a soname corresponding to the major version so that dld.sl refuses to
  # link against other versions.
  version_type=sunos
  need_lib_prefix=no
  need_version=no
  case $host_cpu in
  ia64*)
    shrext_cmds='.so'
    hardcode_into_libs=yes
    dynamic_linker="$host_os dld.so"
    shlibpath_var=LD_LIBRARY_PATH
    shlibpath_overrides_runpath=yes # Unless +noenvvar is specified.
    library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext}$major $libname${shared_ext}'
    soname_spec='${libname}${release}${shared_ext}$major'
    if test "X$HPUX_IA64_MODE" = X32; then
      sys_lib_search_path_spec="/usr/lib/hpux32 /usr/local/lib/hpux32 /usr/local/lib"
    else
      sys_lib_search_path_spec="/usr/lib/hpux64 /usr/local/lib/hpux64"
    fi
    sys_lib_dlsearch_path_spec=$sys_lib_search_path_spec
    ;;
  hppa*64*)
    shrext_cmds='.sl'
    hardcode_into_libs=yes
    dynamic_linker="$host_os dld.sl"
    shlibpath_var=LD_LIBRARY_PATH # How should we handle SHLIB_PATH
    shlibpath_overrides_runpath=yes # Unless +noenvvar is specified.
    library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext}$major $libname${shared_ext}'
    soname_spec='${libname}${release}${shared_ext}$major'
    sys_lib_search_path_spec="/usr/lib/pa20_64 /usr/ccs/lib/pa20_64"
    sys_lib_dlsearch_path_spec=$sys_lib_search_path_spec
    ;;
  *)
    shrext_cmds='.sl'
    dynamic_linker="$host_os dld.sl"
    shlibpath_var=SHLIB_PATH
    shlibpath_overrides_runpath=no # +s is required to enable SHLIB_PATH
    library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext}$major $libname${shared_ext}'
    soname_spec='${libname}${release}${shared_ext}$major'
    ;;
  esac
  # HP-UX runs *really* slowly unless shared libraries are mode 555.
  postinstall_cmds='chmod 555 $lib'
  ;;

interix[[3-9]]*)
  version_type=linux
  need_lib_prefix=no
  need_version=no
  library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext}$major ${libname}${shared_ext}'
  soname_spec='${libname}${release}${shared_ext}$major'
  dynamic_linker='Interix 3.x ld.so.1 (PE, like ELF)'
  shlibpath_var=LD_LIBRARY_PATH
  shlibpath_overrides_runpath=no
  hardcode_into_libs=yes
  ;;

irix5* | irix6* | nonstopux*)
  case $host_os in
    nonstopux*) version_type=nonstopux ;;
    *)
	if test "$lt_cv_prog_gnu_ld" = yes; then
		version_type=linux
	else
		version_type=irix
	fi ;;
  esac
  need_lib_prefix=no
  need_version=no
  soname_spec='${libname}${release}${shared_ext}$major'
  library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext}$major ${libname}${release}${shared_ext} $libname${shared_ext}'
  case $host_os in
  irix5* | nonstopux*)
    libsuff= shlibsuff=
    ;;
  *)
    case $LD in # libtool.m4 will add one of these switches to LD
    *-32|*"-32 "|*-melf32bsmip|*"-melf32bsmip ")
      libsuff= shlibsuff= libmagic=32-bit;;
    *-n32|*"-n32 "|*-melf32bmipn32|*"-melf32bmipn32 ")
      libsuff=32 shlibsuff=N32 libmagic=N32;;
    *-64|*"-64 "|*-melf64bmip|*"-melf64bmip ")
      libsuff=64 shlibsuff=64 libmagic=64-bit;;
    *) libsuff= shlibsuff= libmagic=never-match;;
    esac
    ;;
  esac
  shlibpath_var=LD_LIBRARY${shlibsuff}_PATH
  shlibpath_overrides_runpath=no
  sys_lib_search_path_spec="/usr/lib${libsuff} /lib${libsuff} /usr/local/lib${libsuff}"
  sys_lib_dlsearch_path_spec="/usr/lib${libsuff} /lib${libsuff}"
  hardcode_into_libs=yes
  ;;

# No shared lib support for Linux oldld, aout, or coff.
linux*oldld* | linux*aout* | linux*coff*)
  dynamic_linker=no
  ;;

# This must be Linux ELF.
linux* | k*bsd*-gnu | kopensolaris*-gnu)
  version_type=linux
  need_lib_prefix=no
  need_version=no
  library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext}$major $libname${shared_ext}'
  soname_spec='${libname}${release}${shared_ext}$major'
  finish_cmds='PATH="\$PATH:/sbin" ldconfig -n $libdir'
  shlibpath_var=LD_LIBRARY_PATH
  shlibpath_overrides_runpath=no
  # Some binutils ld are patched to set DT_RUNPATH
  save_LDFLAGS=$LDFLAGS
  save_libdir=$libdir
  eval "libdir=/foo; wl=\"$_LT_TAGVAR(lt_prog_compiler_wl, $1)\"; \
       LDFLAGS=\"\$LDFLAGS $_LT_TAGVAR(hardcode_libdir_flag_spec, $1)\""
  AC_LINK_IFELSE([AC_LANG_PROGRAM([],[])],
    [AS_IF([ ($OBJDUMP -p conftest$ac_exeext) 2>/dev/null | grep "RUNPATH.*$libdir" >/dev/null],
       [shlibpath_overrides_runpath=yes])])
  LDFLAGS=$save_LDFLAGS
  libdir=$save_libdir

  # This implies no fast_install, which is unacceptable.
  # Some rework will be needed to allow for fast_install
  # before this can be enabled.
  hardcode_into_libs=yes

  # Append ld.so.conf contents to the search path
  if test -f /etc/ld.so.conf; then
    lt_ld_extra=`awk '/^include / { system(sprintf("cd /etc; cat %s 2>/dev/null", \[$]2)); skip = 1; } { if (!skip) print \[$]0; skip = 0; }' < /etc/ld.so.conf | $SED -e 's/#.*//;/^[	 ]*hwcap[	 ]/d;s/[:,	]/ /g;s/=[^=]*$//;s/=[^= ]* / /g;/^$/d' | tr '\n' ' '`
    sys_lib_dlsearch_path_spec="/lib /usr/lib $lt_ld_extra"
  fi

  # We used to test for /lib/ld.so.1 and disable shared libraries on
  # powerpc, because MkLinux only supported shared libraries with the
  # GNU dynamic linker.  Since this was broken with cross compilers,
  # most powerpc-linux boxes support dynamic linking these days and
  # people can always --disable-shared, the test was removed, and we
  # assume the GNU/Linux dynamic linker is in use.
  dynamic_linker='GNU/Linux ld.so'
  ;;

netbsdelf*-gnu)
  version_type=linux
  need_lib_prefix=no
  need_version=no
  library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext}$major ${libname}${shared_ext}'
  soname_spec='${libname}${release}${shared_ext}$major'
  shlibpath_var=LD_LIBRARY_PATH
  shlibpath_overrides_runpath=no
  hardcode_into_libs=yes
  dynamic_linker='NetBSD ld.elf_so'
  ;;

netbsd*)
  version_type=sunos
  need_lib_prefix=no
  need_version=no
  if echo __ELF__ | $CC -E - | $GREP __ELF__ >/dev/null; then
    library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${shared_ext}$versuffix'
    finish_cmds='PATH="\$PATH:/sbin" ldconfig -m $libdir'
    dynamic_linker='NetBSD (a.out) ld.so'
  else
    library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext}$major ${libname}${shared_ext}'
    soname_spec='${libname}${release}${shared_ext}$major'
    dynamic_linker='NetBSD ld.elf_so'
  fi
  shlibpath_var=LD_LIBRARY_PATH
  shlibpath_overrides_runpath=yes
  hardcode_into_libs=yes
  ;;

newsos6)
  version_type=linux
  library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext}$major $libname${shared_ext}'
  shlibpath_var=LD_LIBRARY_PATH
  shlibpath_overrides_runpath=yes
  ;;

*nto* | *qnx*)
  version_type=qnx
  need_lib_prefix=no
  need_version=no
  library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext}$major $libname${shared_ext}'
  soname_spec='${libname}${release}${shared_ext}$major'
  shlibpath_var=LD_LIBRARY_PATH
  shlibpath_overrides_runpath=no
  hardcode_into_libs=yes
  dynamic_linker='ldqnx.so'
  ;;

openbsd*)
  version_type=sunos
  sys_lib_dlsearch_path_spec="/usr/lib"
  need_lib_prefix=no
  # Some older versions of OpenBSD (3.3 at least) *do* need versioned libs.
  case $host_os in
    openbsd3.3 | openbsd3.3.*)	need_version=yes ;;
    *)				need_version=no  ;;
  esac
  library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${shared_ext}$versuffix'
  finish_cmds='PATH="\$PATH:/sbin" ldconfig -m $libdir'
  shlibpath_var=LD_LIBRARY_PATH
  if test -z "`echo __ELF__ | $CC -E - | $GREP __ELF__`" || test "$host_os-$host_cpu" = "openbsd2.8-powerpc"; then
    case $host_os in
      openbsd2.[[89]] | openbsd2.[[89]].*)
	shlibpath_overrides_runpath=no
	;;
      *)
	shlibpath_overrides_runpath=yes
	;;
      esac
  else
    shlibpath_overrides_runpath=yes
  fi
  ;;

os2*)
  libname_spec='$name'
  shrext_cmds=".dll"
  need_lib_prefix=no
  library_names_spec='$libname${shared_ext} $libname.a'
  dynamic_linker='OS/2 ld.exe'
  shlibpath_var=LIBPATH
  ;;

osf3* | osf4* | osf5*)
  version_type=osf
  need_lib_prefix=no
  need_version=no
  soname_spec='${libname}${release}${shared_ext}$major'
  library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext}$major $libname${shared_ext}'
  shlibpath_var=LD_LIBRARY_PATH
  sys_lib_search_path_spec="/usr/shlib /usr/ccs/lib /usr/lib/cmplrs/cc /usr/lib /usr/local/lib /var/shlib"
  sys_lib_dlsearch_path_spec="$sys_lib_search_path_spec"
  ;;

rdos*)
  dynamic_linker=no
  ;;

solaris*)
  version_type=linux
  need_lib_prefix=no
  need_version=no
  library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext}$major $libname${shared_ext}'
  soname_spec='${libname}${release}${shared_ext}$major'
  shlibpath_var=LD_LIBRARY_PATH
  shlibpath_overrides_runpath=yes
  hardcode_into_libs=yes
  # ldd complains unless libraries are executable
  postinstall_cmds='chmod +x $lib'
  ;;

sunos4*)
  version_type=sunos
  library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${shared_ext}$versuffix'
  finish_cmds='PATH="\$PATH:/usr/etc" ldconfig $libdir'
  shlibpath_var=LD_LIBRARY_PATH
  shlibpath_overrides_runpath=yes
  if test "$with_gnu_ld" = yes; then
    need_lib_prefix=no
  fi
  need_version=yes
  ;;

sysv4 | sysv4.3*)
  version_type=linux
  library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext}$major $libname${shared_ext}'
  soname_spec='${libname}${release}${shared_ext}$major'
  shlibpath_var=LD_LIBRARY_PATH
  case $host_vendor in
    sni)
      shlibpath_overrides_runpath=no
      need_lib_prefix=no
      runpath_var=LD_RUN_PATH
      ;;
    siemens)
      need_lib_prefix=no
      ;;
    motorola)
      need_lib_prefix=no
      need_version=no
      shlibpath_overrides_runpath=no
      sys_lib_search_path_spec='/lib /usr/lib /usr/ccs/lib'
      ;;
  esac
  ;;

sysv4*MP*)
  if test -d /usr/nec ;then
    version_type=linux
    library_names_spec='$libname${shared_ext}.$versuffix $libname${shared_ext}.$major $libname${shared_ext}'
    soname_spec='$libname${shared_ext}.$major'
    shlibpath_var=LD_LIBRARY_PATH
  fi
  ;;

sysv5* | sco3.2v5* | sco5v6* | unixware* | OpenUNIX* | sysv4*uw2*)
  version_type=freebsd-elf
  need_lib_prefix=no
  need_version=no
  library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext} $libname${shared_ext}'
  soname_spec='${libname}${release}${shared_ext}$major'
  shlibpath_var=LD_LIBRARY_PATH
  shlibpath_overrides_runpath=yes
  hardcode_into_libs=yes
  if test "$with_gnu_ld" = yes; then
    sys_lib_search_path_spec='/usr/local/lib /usr/gnu/lib /usr/ccs/lib /usr/lib /lib'
  else
    sys_lib_search_path_spec='/usr/ccs/lib /usr/lib'
    case $host_os in
      sco3.2v5*)
        sys_lib_search_path_spec="$sys_lib_search_path_spec /lib"
	;;
    esac
  fi
  sys_lib_dlsearch_path_spec='/usr/lib'
  ;;

tpf*)
  # TPF is a cross-target only.  Preferred cross-host = GNU/Linux.
  version_type=linux
  need_lib_prefix=no
  need_version=no
  library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext}$major $libname${shared_ext}'
  shlibpath_var=LD_LIBRARY_PATH
  shlibpath_overrides_runpath=no
  hardcode_into_libs=yes
  ;;

uts4*)
  version_type=linux
  library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext}$major $libname${shared_ext}'
  soname_spec='${libname}${release}${shared_ext}$major'
  shlibpath_var=LD_LIBRARY_PATH
  ;;

*)
  dynamic_linker=no
  ;;
esac
AC_MSG_RESULT([$dynamic_linker])
test "$dynamic_linker" = no && can_build_shared=no

variables_saved_for_relink="PATH $shlibpath_var $runpath_var"
if test "$GCC" = yes; then
  variables_saved_for_relink="$variables_saved_for_relink GCC_EXEC_PREFIX COMPILER_PATH LIBRARY_PATH"
fi

if test "${lt_cv_sys_lib_search_path_spec+set}" = set; then
  sys_lib_search_path_spec="$lt_cv_sys_lib_search_path_spec"
fi
if test "${lt_cv_sys_lib_dlsearch_path_spec+set}" = set; then
  sys_lib_dlsearch_path_spec="$lt_cv_sys_lib_dlsearch_path_spec"
fi

_LT_DECL([], [variables_saved_for_relink], [1],
    [Variables whose values should be saved in libtool wrapper scripts and
    restored at link time])
_LT_DECL([], [need_lib_prefix], [0],
    [Do we need the "lib" prefix for modules?])
_LT_DECL([], [need_version], [0], [Do we need a version for libraries?])
_LT_DECL([], [version_type], [0], [Library versioning type])
_LT_DECL([], [runpath_var], [0],  [Shared library runtime path variable])
_LT_DECL([], [shlibpath_var], [0],[Shared library path variable])
_LT_DECL([], [shlibpath_overrides_runpath], [0],
    [Is shlibpath searched before the hard-coded library search path?])
_LT_DECL([], [libname_spec], [1], [Format of library name prefix])
_LT_DECL([], [library_names_spec], [1],
    [[List of archive names.  First name is the real one, the rest are links.
    The last name is the one that the linker finds with -lNAME]])
_LT_DECL([], [soname_spec], [1],
    [[The coded name of the library, if different from the real name]])
_LT_DECL([], [postinstall_cmds], [2],
    [Command to use after installation of a shared archive])
_LT_DECL([], [postuninstall_cmds], [2],
    [Command to use after uninstallation of a shared archive])
_LT_DECL([], [finish_cmds], [2],
    [Commands used to finish a libtool library installation in a directory])
_LT_DECL([], [finish_eval], [1],
    [[As "finish_cmds", except a single script fragment to be evaled but
    not shown]])
_LT_DECL([], [hardcode_into_libs], [0],
    [Whether we should hardcode library paths into libraries])
_LT_DECL([], [sys_lib_search_path_spec], [2],
    [Compile-time system search path for libraries])
_LT_DECL([], [sys_lib_dlsearch_path_spec], [2],
    [Run-time system search path for libraries])
])# _LT_SYS_DYNAMIC_LINKER


# _LT_PATH_TOOL_PREFIX(TOOL)
# --------------------------
# find a file program which can recognize shared library
AC_DEFUN([_LT_PATH_TOOL_PREFIX],
[m4_require([_LT_DECL_EGREP])dnl
AC_MSG_CHECKING([for $1])
AC_CACHE_VAL(lt_cv_path_MAGIC_CMD,
[case $MAGIC_CMD in
[[\\/*] |  ?:[\\/]*])
  lt_cv_path_MAGIC_CMD="$MAGIC_CMD" # Let the user override the test with a path.
  ;;
*)
  lt_save_MAGIC_CMD="$MAGIC_CMD"
  lt_save_ifs="$IFS"; IFS=$PATH_SEPARATOR
dnl $ac_dummy forces splitting on constant user-supplied paths.
dnl POSIX.2 word splitting is done only on the output of word expansions,
dnl not every word.  This closes a longstanding sh security hole.
  ac_dummy="m4_if([$2], , $PATH, [$2])"
  for ac_dir in $ac_dummy; do
    IFS="$lt_save_ifs"
    test -z "$ac_dir" && ac_dir=.
    if test -f $ac_dir/$1; then
      lt_cv_path_MAGIC_CMD="$ac_dir/$1"
      if test -n "$file_magic_test_file"; then
	case $deplibs_check_method in
	"file_magic "*)
	  file_magic_regex=`expr "$deplibs_check_method" : "file_magic \(.*\)"`
	  MAGIC_CMD="$lt_cv_path_MAGIC_CMD"
	  if eval $file_magic_cmd \$file_magic_test_file 2> /dev/null |
	    $EGREP "$file_magic_regex" > /dev/null; then
	    :
	  else
	    cat <<_LT_EOF 1>&2

*** Warning: the command libtool uses to detect shared libraries,
*** $file_magic_cmd, produces output that libtool cannot recognize.
*** The result is that libtool may fail to recognize shared libraries
*** as such.  This will affect the creation of libtool libraries that
*** depend on shared libraries, but programs linked with such libtool
*** libraries will work regardless of this problem.  Nevertheless, you
*** may want to report the problem to your system manager and/or to
*** bug-libtool@gnu.org

_LT_EOF
	  fi ;;
	esac
      fi
      break
    fi
  done
  IFS="$lt_save_ifs"
  MAGIC_CMD="$lt_save_MAGIC_CMD"
  ;;
esac])
MAGIC_CMD="$lt_cv_path_MAGIC_CMD"
if test -n "$MAGIC_CMD"; then
  AC_MSG_RESULT($MAGIC_CMD)
else
  AC_MSG_RESULT(no)
fi
_LT_DECL([], [MAGIC_CMD], [0],
	 [Used to examine libraries when file_magic_cmd begins with "file"])dnl
])# _LT_PATH_TOOL_PREFIX

# Old name:
AU_ALIAS([AC_PATH_TOOL_PREFIX], [_LT_PATH_TOOL_PREFIX])
dnl aclocal-1.4 backwards compatibility:
dnl AC_DEFUN([AC_PATH_TOOL_PREFIX], [])


# _LT_PATH_MAGIC
# --------------
# find a file program which can recognize a shared library
m4_defun([_LT_PATH_MAGIC],
[_LT_PATH_TOOL_PREFIX(${ac_tool_prefix}file, /usr/bin$PATH_SEPARATOR$PATH)
if test -z "$lt_cv_path_MAGIC_CMD"; then
  if test -n "$ac_tool_prefix"; then
    _LT_PATH_TOOL_PREFIX(file, /usr/bin$PATH_SEPARATOR$PATH)
  else
    MAGIC_CMD=:
  fi
fi
])# _LT_PATH_MAGIC


# LT_PATH_LD
# ----------
# find the pathname to the GNU or non-GNU linker
AC_DEFUN([LT_PATH_LD],
[AC_REQUIRE([AC_PROG_CC])dnl
AC_REQUIRE([AC_CANONICAL_HOST])dnl
AC_REQUIRE([AC_CANONICAL_BUILD])dnl
m4_require([_LT_DECL_SED])dnl
m4_require([_LT_DECL_EGREP])dnl

AC_ARG_WITH([gnu-ld],
    [AS_HELP_STRING([--with-gnu-ld],
	[assume the C compiler uses GNU ld @<:@default=no@:>@])],
    [test "$withval" = no || with_gnu_ld=yes],
    [with_gnu_ld=no])dnl

ac_prog=ld
if test "$GCC" = yes; then
  # Check if gcc -print-prog-name=ld gives a path.
  AC_MSG_CHECKING([for ld used by $CC])
  case $host in
  *-*-mingw*)
    # gcc leaves a trailing carriage return which upsets mingw
    ac_prog=`($CC -print-prog-name=ld) 2>&5 | tr -d '\015'` ;;
  *)
    ac_prog=`($CC -print-prog-name=ld) 2>&5` ;;
  esac
  case $ac_prog in
    # Accept absolute paths.
    [[\\/]]* | ?:[[\\/]]*)
      re_direlt='/[[^/]][[^/]]*/\.\./'
      # Canonicalize the pathname of ld
      ac_prog=`$ECHO "$ac_prog"| $SED 's%\\\\%/%g'`
      while $ECHO "$ac_prog" | $GREP "$re_direlt" > /dev/null 2>&1; do
	ac_prog=`$ECHO $ac_prog| $SED "s%$re_direlt%/%"`
      done
      test -z "$LD" && LD="$ac_prog"
      ;;
  "")
    # If it fails, then pretend we aren't using GCC.
    ac_prog=ld
    ;;
  *)
    # If it is relative, then search for the first ld in PATH.
    with_gnu_ld=unknown
    ;;
  esac
elif test "$with_gnu_ld" = yes; then
  AC_MSG_CHECKING([for GNU ld])
else
  AC_MSG_CHECKING([for non-GNU ld])
fi
AC_CACHE_VAL(lt_cv_path_LD,
[if test -z "$LD"; then
  lt_save_ifs="$IFS"; IFS=$PATH_SEPARATOR
  for ac_dir in $PATH; do
    IFS="$lt_save_ifs"
    test -z "$ac_dir" && ac_dir=.
    if test -f "$ac_dir/$ac_prog" || test -f "$ac_dir/$ac_prog$ac_exeext"; then
      lt_cv_path_LD="$ac_dir/$ac_prog"
      # Check to see if the program is GNU ld.  I'd rather use --version,
      # but apparently some variants of GNU ld only accept -v.
      # Break only if it was the GNU/non-GNU ld that we prefer.
      case `"$lt_cv_path_LD" -v 2>&1 </dev/null` in
      *GNU* | *'with BFD'*)
	test "$with_gnu_ld" != no && break
	;;
      *)
	test "$with_gnu_ld" != yes && break
	;;
      esac
    fi
  done
  IFS="$lt_save_ifs"
else
  lt_cv_path_LD="$LD" # Let the user override the test with a path.
fi])
LD="$lt_cv_path_LD"
if test -n "$LD"; then
  AC_MSG_RESULT($LD)
else
  AC_MSG_RESULT(no)
fi
test -z "$LD" && AC_MSG_ERROR([no acceptable ld found in \$PATH])
_LT_PATH_LD_GNU
AC_SUBST([LD])

_LT_TAGDECL([], [LD], [1], [The linker used to build libraries])
])# LT_PATH_LD

# Old names:
AU_ALIAS([AM_PROG_LD], [LT_PATH_LD])
AU_ALIAS([AC_PROG_LD], [LT_PATH_LD])
dnl aclocal-1.4 backwards compatibility:
dnl AC_DEFUN([AM_PROG_LD], [])
dnl AC_DEFUN([AC_PROG_LD], [])


# _LT_PATH_LD_GNU
#- --------------
m4_defun([_LT_PATH_LD_GNU],
[AC_CACHE_CHECK([if the linker ($LD) is GNU ld], lt_cv_prog_gnu_ld,
[# I'd rather use --version here, but apparently some GNU lds only accept -v.
case `$LD -v 2>&1 </dev/null` in
*GNU* | *'with BFD'*)
  lt_cv_prog_gnu_ld=yes
  ;;
*)
  lt_cv_prog_gnu_ld=no
  ;;
esac])
with_gnu_ld=$lt_cv_prog_gnu_ld
])# _LT_PATH_LD_GNU


# _LT_CMD_RELOAD
# --------------
# find reload flag for linker
#   -- PORTME Some linkers may need a different reload flag.
m4_defun([_LT_CMD_RELOAD],
[AC_CACHE_CHECK([for $LD option to reload object files],
  lt_cv_ld_reload_flag,
  [lt_cv_ld_reload_flag='-r'])
reload_flag=$lt_cv_ld_reload_flag
case $reload_flag in
"" | " "*) ;;
*) reload_flag=" $reload_flag" ;;
esac
reload_cmds='$LD$reload_flag -o $output$reload_objs'
case $host_os in
  darwin*)
    if test "$GCC" = yes; then
      reload_cmds='$LTCC $LTCFLAGS -nostdlib ${wl}-r -o $output$reload_objs'
    else
      reload_cmds='$LD$reload_flag -o $output$reload_objs'
    fi
    ;;
esac
_LT_DECL([], [reload_flag], [1], [How to create reloadable object files])dnl
_LT_DECL([], [reload_cmds], [2])dnl
])# _LT_CMD_RELOAD


# _LT_CHECK_MAGIC_METHOD
# ----------------------
# how to check for library dependencies
#  -- PORTME fill in with the dynamic library characteristics
m4_defun([_LT_CHECK_MAGIC_METHOD],
[m4_require([_LT_DECL_EGREP])
m4_require([_LT_DECL_OBJDUMP])
AC_CACHE_CHECK([how to recognize dependent libraries],
lt_cv_deplibs_check_method,
[lt_cv_file_magic_cmd='$MAGIC_CMD'
lt_cv_file_magic_test_file=
lt_cv_deplibs_check_method='unknown'
# Need to set the preceding variable on all platforms that support
# interlibrary dependencies.
# 'none' -- dependencies not supported.
# `unknown' -- same as none, but documents that we really don't know.
# 'pass_all' -- all dependencies passed with no checks.
# 'test_compile' -- check by making test program.
# 'file_magic [[regex]]' -- check by looking for files in library path
# which responds to the $file_magic_cmd with a given extended regex.
# If you have `file' or equivalent on your system and you're not sure
# whether `pass_all' will *always* work, you probably want this one.

case $host_os in
aix[[4-9]]*)
  lt_cv_deplibs_check_method=pass_all
  ;;

beos*)
  lt_cv_deplibs_check_method=pass_all
  ;;

bsdi[[45]]*)
  lt_cv_deplibs_check_method='file_magic ELF [[0-9]][[0-9]]*-bit [[ML]]SB (shared object|dynamic lib)'
  lt_cv_file_magic_cmd='/usr/bin/file -L'
  lt_cv_file_magic_test_file=/shlib/libc.so
  ;;

cygwin*)
  # func_win32_libid is a shell function defined in ltmain.sh
  lt_cv_deplibs_check_method='file_magic ^x86 archive import|^x86 DLL'
  lt_cv_file_magic_cmd='func_win32_libid'
  ;;

mingw* | pw32*)
  # Base MSYS/MinGW do not provide the 'file' command needed by
  # func_win32_libid shell function, so use a weaker test based on 'objdump',
  # unless we find 'file', for example because we are cross-compiling.
  if ( file / ) >/dev/null 2>&1; then
    lt_cv_deplibs_check_method='file_magic ^x86 archive import|^x86 DLL'
    lt_cv_file_magic_cmd='func_win32_libid'
  else
    lt_cv_deplibs_check_method='file_magic file format pei*-i386(.*architecture: i386)?'
    lt_cv_file_magic_cmd='$OBJDUMP -f'
  fi
  ;;

cegcc)
  # use the weaker test based on 'objdump'. See mingw*.
  lt_cv_deplibs_check_method='file_magic file format pe-arm-.*little(.*architecture: arm)?'
  lt_cv_file_magic_cmd='$OBJDUMP -f'
  ;;

darwin* | rhapsody*)
  lt_cv_deplibs_check_method=pass_all
  ;;

freebsd* | dragonfly*)
  if echo __ELF__ | $CC -E - | $GREP __ELF__ > /dev/null; then
    case $host_cpu in
    i*86 )
      # Not sure whether the presence of OpenBSD here was a mistake.
      # Let's accept both of them until this is cleared up.
      lt_cv_deplibs_check_method='file_magic (FreeBSD|OpenBSD|DragonFly)/i[[3-9]]86 (compact )?demand paged shared library'
      lt_cv_file_magic_cmd=/usr/bin/file
      lt_cv_file_magic_test_file=`echo /usr/lib/libc.so.*`
      ;;
    esac
  else
    lt_cv_deplibs_check_method=pass_all
  fi
  ;;

gnu*)
  lt_cv_deplibs_check_method=pass_all
  ;;

hpux10.20* | hpux11*)
  lt_cv_file_magic_cmd=/usr/bin/file
  case $host_cpu in
  ia64*)
    lt_cv_deplibs_check_method='file_magic (s[[0-9]][[0-9]][[0-9]]|ELF-[[0-9]][[0-9]]) shared object file - IA64'
    lt_cv_file_magic_test_file=/usr/lib/hpux32/libc.so
    ;;
  hppa*64*)
    [lt_cv_deplibs_check_method='file_magic (s[0-9][0-9][0-9]|ELF-[0-9][0-9]) shared object file - PA-RISC [0-9].[0-9]']
    lt_cv_file_magic_test_file=/usr/lib/pa20_64/libc.sl
    ;;
  *)
    lt_cv_deplibs_check_method='file_magic (s[[0-9]][[0-9]][[0-9]]|PA-RISC[[0-9]].[[0-9]]) shared library'
    lt_cv_file_magic_test_file=/usr/lib/libc.sl
    ;;
  esac
  ;;

interix[[3-9]]*)
  # PIC code is broken on Interix 3.x, that's why |\.a not |_pic\.a here
  lt_cv_deplibs_check_method='match_pattern /lib[[^/]]+(\.so|\.a)$'
  ;;

irix5* | irix6* | nonstopux*)
  case $LD in
  *-32|*"-32 ") libmagic=32-bit;;
  *-n32|*"-n32 ") libmagic=N32;;
  *-64|*"-64 ") libmagic=64-bit;;
  *) libmagic=never-match;;
  esac
  lt_cv_deplibs_check_method=pass_all
  ;;

# This must be Linux ELF.
linux* | k*bsd*-gnu | kopensolaris*-gnu)
  lt_cv_deplibs_check_method=pass_all
  ;;

netbsd* | netbsdelf*-gnu)
  if echo __ELF__ | $CC -E - | $GREP __ELF__ > /dev/null; then
    lt_cv_deplibs_check_method='match_pattern /lib[[^/]]+(\.so\.[[0-9]]+\.[[0-9]]+|_pic\.a)$'
  else
    lt_cv_deplibs_check_method='match_pattern /lib[[^/]]+(\.so|_pic\.a)$'
  fi
  ;;

newos6*)
  lt_cv_deplibs_check_method='file_magic ELF [[0-9]][[0-9]]*-bit [[ML]]SB (executable|dynamic lib)'
  lt_cv_file_magic_cmd=/usr/bin/file
  lt_cv_file_magic_test_file=/usr/lib/libnls.so
  ;;

*nto* | *qnx*)
  lt_cv_deplibs_check_method=pass_all
  ;;

openbsd*)
  if test -z "`echo __ELF__ | $CC -E - | $GREP __ELF__`" || test "$host_os-$host_cpu" = "openbsd2.8-powerpc"; then
    lt_cv_deplibs_check_method='match_pattern /lib[[^/]]+(\.so\.[[0-9]]+\.[[0-9]]+|\.so|_pic\.a)$'
  else
    lt_cv_deplibs_check_method='match_pattern /lib[[^/]]+(\.so\.[[0-9]]+\.[[0-9]]+|_pic\.a)$'
  fi
  ;;

osf3* | osf4* | osf5*)
  lt_cv_deplibs_check_method=pass_all
  ;;

rdos*)
  lt_cv_deplibs_check_method=pass_all
  ;;

solaris*)
  lt_cv_deplibs_check_method=pass_all
  ;;

sysv5* | sco3.2v5* | sco5v6* | unixware* | OpenUNIX* | sysv4*uw2*)
  lt_cv_deplibs_check_method=pass_all
  ;;

sysv4 | sysv4.3*)
  case $host_vendor in
  motorola)
    lt_cv_deplibs_check_method='file_magic ELF [[0-9]][[0-9]]*-bit [[ML]]SB (shared object|dynamic lib) M[[0-9]][[0-9]]* Version [[0-9]]'
    lt_cv_file_magic_test_file=`echo /usr/lib/libc.so*`
    ;;
  ncr)
    lt_cv_deplibs_check_method=pass_all
    ;;
  sequent)
    lt_cv_file_magic_cmd='/bin/file'
    lt_cv_deplibs_check_method='file_magic ELF [[0-9]][# libt*-bit [[LM]]SB (shared object|dynamic lib )'
    ;;
  sni)Autoclt_cv_file_magic_cmd='/bin/ht (-Autocopyrigdeplibs_check_method="ht (C) 199 ELF ool.m4 ool.m4 - Configure libst system. "#   Copyright (C) 1996testght (=/libn Mac.soAutoconf-*-iemens
#   Copyrig2001, 2003, 2004, 200pass_allAutoconf-*pcile is free software; the Free Software Foundation esac
oconf
tpf*
#   free software; the Free Software Foun;;
e it,])
ht (C) 1996, 19$opyright (C) 1996, 1
2001, 2003, 2004, 200ine([_L2001, 2003, 2004, 20
n by -z "$2001, 2003, 2004, 20" && 2001, 2003, 2004, 200unknown

_LT_DECL([], [2001, 2003, 2004, 20ound1],Autoc[M4, 20 to 03, 2 whether    endentem. raries are ool for the hs]) Software Foundht (C) 1996, 1ten by GordonCommanigkeiuse96
#n         2006, 2007,  == 5,
#       "])
])# SoftCHECK_MAGIC_METHOD


# LT_PATH_NM
# -ee Softwa
# fie ithe pathnamegkeia BSD- or MS-compatible ther lister
AC_DEFUN([hed by the],
[AC_REQUIRE(ion.PROG_CC])dnlr opCACHEblic L([forion 2 of
# the License, or (at you (nm)],out
# m; ei_NM,
[if  2001,n "$NM";ation
  # Letationuser overrideationn by.thout
# m as par= or l
elsethout
nm_to003, 2="${ac_tool_prefix}nmdatif a program oibution terms       2001"$build" = "$hostlibrary thder the
# same distr the
# same d hat yofi,
# orout
tmp_nm in t it will be us; dt, 199lt_save_ifs="$IFS"; IFS=$ by tSEPARATORbutedWITHac_dirARRAN by  /usr/ccs7, 19elf PURPOSE.  Se PURPOucb 7, 1en the im  MERCat ited warradation a progr 200OR A P     OR A P= youould ANY W=ceived a/t iteral Pu shouldf a progrf "$# along || Libtool; see theeiveexeext" ibrary 	# Ce useto seeGNU Lhe nm acceptsrsion 2he Lic flag. dowAddingtp://`sed 1q' prevents false positives on HP-UX, which says: dow  nm: 008 Fre option "B" ignored dowTru64's/wwwhe Llains that /dev/null is an invalior the h ht (
	case ` see the f-Bserial 56 L2>&1 | by w'1q'` in
	*erial 56 * | *'I

# LT_ht ( of
PREREQ(type'*)
	ou may include thi ANY WA-B"un([breakun([;;
	efun([N)
# ------------p-----
# Complain and exit if thi  s libtool vfun([([LT_PREREQ],
[m4_if(m4_vepsion_n_compare(m(m4_de  m4_fatal([Libtool vers${LT_PREREQ],
[m4_if(m4_"} # keeptp://first match, butuired]continue # so)

# swe can tryed foundaonU Liat supportsion l.htmsuired],
		  e it,e(m4_dee it, wITNESbut   donundeore details.
#
# You she `pwd`:     [$2])])


# no}
fi])
f a progat ity include " != "nolibrary the thi whitespace inile unde# Didn'Q(VEnd anyusualhe License, or (at you, lookESS Fdumpbin youon tic LiTOOLS(DUMPBIN, ["8])dnl  -symbols" "link -8])d[$0], [LT_], :
#  AC_SUBST([DEFAULT]
#   well withDEFAULTn `pwd: distributede thiL_INIT]),
# bufi, 2001, 200 in &&LT_Cnmr opPUT])dnNMGNU Libtool is fr vern by  [Aion 2 of
# the License, or (at youxceptiion to the GNU Gep://wyou distribu$NM) interfacet:
m whitenm__DLLAZY_OR_
 NOW|LT_MULTI_MODULE)="sualong wiecho "int some_varianse,= 0;" >omplfool, t, a ct
  (evalptions.\"\$as_me:__oline__: eivehe Lile\"" >&AS_MESSAGE_LOG_FD
#   requiceiveIRE([LT" 2>on.m4
dnlerr
#  cation.m4
dnlerrIONS_VERSION])dnl
AC we require an AC_DEFUNed macro:
AC_RNM \\\"on.m4
dnl unl thextPROGOPTIONS_VERSION])dnl
AC_REQUIRE([LTLT_PG_LTMAIN])dnl

dnl Pa"ION])dnl
AC_REQUrsion.m4
dnloutIRE([LTVERSION_VERSION])dnl
AC_REQUIRE([LTOBSOLETE_VERSION])dnl
m4_require([outpuo rebONS_VERSION])dnl
AC_REQ[LTVERSION_VEoutON])dnl
AC_REQUIRE([LTOif $GREP 'External.*ltsugar.m4, o'l

_LT_SETUP

#serial 56 distributed inl aclocal doesn'tMS58])dnl l,
# but rmool;on.m4
dn*Generalhed by the 
# Old_EOF|s:
AU_ALIAS([AMpecial defauny later ve)ibility:
dnlspecialUN([AC_PROG_LIBTOOLdnl aclocal-1.4 backwardsC_DEFUN([ility:], [] option) al AC_DEFUN([ACOL], []------
# CaAC_DEFUN([AM_])ublishedLIB_e Free Softw
#it, 199WITHmath is paryr option) any  crosersion.
#
# As a spCANONICAL_HOSTxceptiLIBM=
N)
# ol isf th*-*-beosversi-*-cygwin *[[\\/]pw32 *[[\\/]darache
#  # These system AC_'t hav (atbm, of
*[[\\/need is we;;
*-ncr-sysv4.3]]disse AC_INCLIB(mw, _mw
# LT03, 2l, | *[["-lmw"
done
cc_basename=, cos" | $Xse$| *[ -lm 's%.*) b's%.*/%%' -e "s%^$host_alias-%%

# _LT_FILe it,atch unexp| *[nl aclocal crosskwards comptibility:
dnl
cc_basenamN([AC_PR in $1L], [])


# _LT_CC_BASENAME(CC)
# -------------------
# Cabeen set
# sensiappers  PublOMPILER_NO_RTTI([TAGNAME]) Free Softwar
])# _LT_FILEUTILS_DE
m4_defun([CP="cp -f"}
: ${MV="ersim4_require _LT_STAG"cp -f"}
nl
m4_pETUP],
VAR(lt_progGAR_VERSr_no_ GNUtin_.htm, $1)=
e well withGCCLibtyesibrary thCANONICAL_HOST])dnl
AC_REQUIRE([AC_CANONICAL_BUIL' -fno-[AC_CAN'
ias], [cp -f"}
:OPTION(of a$
AC_REQUntains unu[0])drttiuild_aexnu.oionsy Gordo whites)dnl
AC_REQUIlias_, [The bui Gordonild_alias], [0], [The build [y GordonCANONICAL_HOST])dnl
AC_REQUIRE([AC_CANONICAL_BUIL"$CANONICAL_HOST])dnl
AC_REQUIRE([AC_CANONICAL_BUIuild_alias], [0], [The bui Genfi_CANONICware FRE([AC_CANONICAR_NOW|L])dnl
AC_REQUIRE([AC_CANONICAten by G	tribLT_DEC.htmed fturn off [AC_CAN funce buileneral Publp -f"}
: ${MV="[: ${CP="cMD_GLOBAL_SYMBOLS{RM="rm -f"}
])# _LT_FILEAULTS


# _LT_SE[Object file suff1""; do
  case $cc_temp in
    compile on.
#
# As a special exception 
#
# As a_PROG_LIBTOOLS_DEFAULTS])dnl
m4_requLDe([_LTdefun([_LT_SETUPware_SE])dnl
m4_require([_LT_CMD_REEine()dnl
m4_require([_LT_C],
[AC_REQUIRE([AC_ownloadeWITHcibute it agrabtp://raw 0], [L_EOF|Lfollowed by CAL_SYMBOfrom nm.l
m4MSG AC_INING([4_require([par]]coNMuilddirOL_INInl
_LT_DEC the hOOL]n to theVAL(OW|LT_Msys_global_0], [L_pip)$])[
tcc | pu GNU ane default])

# sworkFounat least a few oldurify |s.
# [Theym4_reOL_INIUltrix.  W concould bept Nerme cn-n "${Z?!! ;)]ARCHIVaractribclass describobtaNM t remoAL_SYMBOcodes.
sym_COM='[[BCDEGRST]]'ARCHRegexped f-----AL_SYMB])

# s buibew.gnusby wdirectlyOL_INICILER]pat='\([[_A-Za-z2006 collecl.m4 -\)_BACKDefinpurify |-specific ar.m4, os.\\/]]compil_osf thaixEUTILER])dnl
_LT_PRCHO_BT_FIL]ccache ) mingwvers   distccegccable, the probleABCDGISTW # vanishhpuiable, well withvironcpuLibtia64distributedLLECT_NAMES+setOG_ECHO_BIR],
[c;;
irixversnonston
    COER])dnl
_LT_PROG_ECHO_Btutioos withoER])dnl
_LT_PROGQ backslashifsolaris
# metacharactersDRre still acco3.2v5
# metacharacter
  # vanish;
  es2uw2e_subst='s/\([["`$\\]]\)/\\\1/g5verssco5v6versunixwareversOpenUNIXX${COLLECT_NAMES+s`$\\]]\)/\\\1/g'_subst='s/\([["`FNSTUckslashife it,
# If we'rbuilobtaGNU nm,braryand/oits standarNO_GT_TAG_COMPILN)
# -d se-Vmplaiif th*GNUversiowith BFDdefuCOLLECT_NAMES+set}"R != Xspansion of aTransformINITextfi

_e_subst'ecro:T_DLersiproper C declarae buUBSTSif t_GLOB_S (esp.Fount CO)quotk data te i_COMst_os in
differently,
 the nd/othis general approach.
ugh without removal of \# saote_="by w-n -e 's/^T .* \(.*\)$/e_INITT_DL \1();/p'
ofile=l$ER])dnl*btool
can_build_shachar \1
# A"y expansion of an escaped single quote.
delaL_SYMBOLS])dte isubst'eaddress_subst='s/\*/\\\*/g'

# Globa_EOF|_ld="$ltriables:
ofile=l:  GCC^ or so $/  {arse 1PROG, (void *) 0},# All known linkers rane defaultsane default for v"\2variables
tes\&\2 -z ""_cv_prog_gnu_ld"

old_CC="$CC"
old_CFLAGS=_lib terms "$CFLAGS"

# Set sane defaults for various variables
test -z "$CC" && CC=cc
test -z "$LTCC" &&lib LTCC=$CC
test -z "$LTCFLAGS" && LTCFLAG$CC" && CC=cc
test -z "$LTCC" && LTCC=$CC
test -libz "$LTCFLAGS" && LTCFLAGS=
# Handle CRLFARRA of s tionhivein
opt_cr[\\/]]co GNU nment v of sm\\\\LT_PATH`$ECHO 'x\{0,1\}' | tr x '\015'` # Fifth FcPARTIrLASH
expansion of aTry \\\\UP

y_sirms  underscoreble in \\\\\it.
SS FOR withrfxARRA"" "_"en thdistccansion ofER])dnl,_LTMpat,a

with_MMANDS
elay_LOBAL_SYMBOte iaFIG_LIBTO yousymxfrm="\\1_REQU---
# N\\2 \\2"UP


#WritU LibtLOBAte iC ifileifiers you well with whiteULTI_MODULE)LibtoAS([AM_PROGdistributed# Fak# do([2.58])dnl a

witay TESS FOnyhelp-static_LEN])dnls no vate iDare usingquire([ar.m4, o GNU G# AlsrectoryC++ copy__fastcal([_LT_TAsOL_INIMSVC++ Gordo#, Inc.,
tartCONFIG@ of
? GNU Gugh without removal of \ esc="$AWK ['"\
"LDDIR{last_se])dnl=_INIT([; _INIT([a\$ 3};_CONFIG_L/SINIT([ length .*#relocs.*(pickusin)/{hide[BTOOL_INIT([]=1r'])
ltmain\$ 0!~/T_INIT]) *\|/{nextr'])
ltmain= 0+ UNDEF #
## Acc /for cre\([^|]\)*()#
## Accumulate c{if(TMAIN -------) ----------------f=0};-----~/\(\).- ##
f---- {printf f ? \"T \" : \"D \"------------split(----, a, /\||\r/); mulatea[2], s)r'])
ltmains[1]~/^[@?]/pt incMMAND,MMAND;# So that we canMANDSMMANDumulatend tht,\"@\"); cros atd thenubstr(.


#_dir/l(MMAN))}_CONFIG_Ltingfx=^, and `conf]ltopte unde_REQUIRE_AUX_FILE([ltmain.sh])])ables:
ofile=l.*[[	 ]]\( linkers linkers \) passe passe*, and `conf linpat$LT_PAT$/ linconfLAGS=IR],
distcnloaded from e contion;ipeON+seE(CCrs has  you_LT__UTPUT=nTUP

], [LT_INIT])
dOOL)dnlsion.m4
dnl unless <<SoftEOF
#ifdef __cplus_INI
ild_sha"C" {
#endif
ive fhe
# by var;
bles
MMANDS])LEN]ables)-------------------------{}PUT_LIBTOOL_INIT])

}G_LIBTOOos amain(){MMANDS])
# ='a';-------------);reUIRE(0);}_CANOOUTPS to gAC_TRY_E thrSUGAR_VERS)us' has no vaNowild dire_LT_CMD_G0], [LT GNU Gnat y=on.m4
dnlnm-----     [m4_appendNMT_INIT])
)dnl

dnl P \|ANTY; without removal of \ esc \> $])])])rogram.
#-s "MANDS]tus' has no 


# _y sortobtate iuniquifyobtainedilddir GNU Genif-----ANDS])
# erenceq >ANDS])
# Tcan be dmvool; s,
[_LT_L([$1])
_UILDDIR-----	], [LT([$1])
_LUILDDIR],
---------Mue fsurm4_appewe snagged un([           ----*) ;
m4_defun([fine([LOMMANDS])
# $'CONFIG_SAV>IAS([AC_PROG_LIB	mment marks to the LEN]rt of each line, and a trailinOL)dnl([_LT_OUTrsion.m4
dnl unless UT_LIBTOOL_INIT])


# _LT_CONFIG_LIBTOO([$1],
  	_COMMANDpressithat we_LIBTOOLihas _defRE([LTsubst='s/\*/\\\*/g'

# Global va"' <CONFIG_SAVE_fine([-vS lat >sion.m4
dnl unless'
esent already.
m4_dsion.m4
dnl unless 
/*cc | mappobtabetweenb').
libext=_INIwith_gnus.[$3]
clps  struct {OOL) VARNive f*EOF|nf-*bles
ED?])
*ld="$lt;
}_subpeciaRAM__LTX terloadedval of s[[]] =
LUE,{ "@-------@ariables
test },t([m4_bpatsu$SED "own linkersCC=cc
test -can_ol
can_buest -z "$LTCFLAGS" && LTCFL"?.]$], [], [.])
)])



## ---------------------esent alre\XME: Eliminate VARNAME ##
##  {0riables
test 
};# -----isOUTPUT_arous calprobleWARRAFreesualsubserAME]UT_LIBTFREEBSD_WORKAROUND
omake,
 [DESCbles
t], [1---------etup()ALUE,,
[m4_REQU-----------------------------------patsubst be passed to AC_CONFIG_COMM([m4_bpatsubst([$ld dsubsobtainedtwrectCT_NA	  mvTPUT_LIBTOOL_COMMANDSon.m4stm)dnl

dnl Pun([LT_ed waLIBdetay([lsion_dd_subkeCFLAGdeta[descrsion_y([lt_ifval([$4],
	[lt_dision_[description], l
AC_REQUIRE([LT_PATH_NM])dnl
dnl
AC_REQUIRE([AC_sion_     [m4_append([_subs, [INIT_COMMAon.m4
dntribu copy
}not presenT],
         yeractefi$4])])
   ails.
#
#ecl_dict][descript, [$2], [descr"
	_INIT(options.canno-------op to the whARRAN each li])dnl
AC_REQUIRE([L	],
[casOL_INIT(CL([$1], [$2], [$3], [$4],vaPARTIC


# lt_decl_tag_varnames([ILDDIR],
[cas---------DECL([$1], [$2]ruRANTY; without removal of \ esc----------------------
m4_],
[c---------tions.$l
_Lassum failedbe ugram was:----------------------
m4_[LTVERSION_VE4_define>&5_LIBTOOL], [rLT_INIT])
d_ifval([*[$1],
Do [$2]evalede make sVE_COMMANDS([unlessfor UTPUTDS to generate,
        ([], [host_aliasn_compar--------------------------
# Register INfval([e `pwope well wi rececl_filter([tagged?], [yes], $ibrary thsubst='s/\*/\\\*/g'

# Global var" && [$2], [], lt_decl_varnames)],
  [3], [lt'`$\]], [\\\&])]m4_bmatch([$1], [[ibrary th# See iRESULT(RNAME1)ile undee_varnames([SEokS" && Software Ft removal of \ escapNOW|LT_Mthout removal of \ escapn by GordonTue f---------- of/www.n1..])duce a(at yobtaoft this codeT_DECLC
# _LTGNU Libtool i*/\\\*/g'

# Global va------------
m4_define([lt_d# ----------e_varnamesansion of_lt_decl_filter([r un_single_quote_subst='SEPARATOR], [VARNAME1...])
# --"
old_CFLAGS=y Gordoncv_prog_gnu_ld"

old_CC="$CC"
old_CFLAGS=---------
m4_define([lt_decl_dquote_varnames]names(_ld="$lt pairvalue], [2], $@)])


# lt_decl_varnames_taggac_objext" ed([SEPARATOR], [VARNAME1...])
# ----------------te(m4_default---------------------------------
m4_define([lt_decl_varnames_or
# mm. -ONFIG
_isdd leed_LT_D , [0], [Object file suffi: ${CP="cp -f"}
:PICmv -f"}
: ${RM="rm -f"}
])# _LT_FILEUTILSAULTS


# _LT_SETUP
# --PIC
m4_defun([_LT_SETUP],
[AC_REQUIRE([ACCANONICAL_HOST])dnl
AC_REQUIwlL_BUILDCANONICAL_HOST])dnl
AC_REQUIpicfine([lt_decl_all_varnames],
[_$0(momake,L_BUILD]# See if we are rWITHs which allifth Fn zs], [1],[VAR)m4_rif([$lt:
mCXXdecl$1],
 ++ e set theN)
#sdnl
m4_quo  m4_if(defietcDS to generateGXX$0: too few argume------------------------
m4_define(['-Wl,-Autoc_default([$1], [[, ]])),
     m4_if([$2]'tomake,DECL(LT_PACKnvironment v----ariable,a sensibl AIXto avois_shi
m4_defun([CT_NAMES=
    export COLLECT_N or
IX 5 nowntains unuIA64quot somor
	 _LT_CONFIG_STATUS_DECLARE([VARNAME])
# --B--------ILDDIR],
[cas with ----
migaowithin---------------cpu--------  powergives
# CLARE],
#from 4_reile abUP

Ae foOS4 .sontains uS_DECLARE],
[t_decl_all_varnames],
[_$0(m4_quote(m'-fPICingle quoconf-*----m68kUS_DECLARE],
[$1FIXME:# Add le ; then
  68020to avoto_CMD_dU Libtoois part o------DECLARE],
[ a c# obtained -mvaria'nl
AC_REQGCCing to the GNU ------yth-------AC_Pe write them toliktatus, w40' GNU Genuote_subst"`'])


# _LT_CONFIG_STATUS_DECLARAs, we  -resNFIG_32 -malways(andtore-a4S
# ---------------CK_BUILDDIRited valhe | *[[n thvarian thefereelps us do | osf3([_LT_C4([_LT_Cte_subhem toPIC and], ["\${ZSHdnl
mt | puOST_NA------------- of smoke]ccache ) osdistc.
  if test "X${CO------- othhack andhe absol, [# ourc ---lte builell96
#
#   it andbeingRE(_lt_va[AC_Cdnl
minclus_auxames]dll (DECL(hN+setexns u[_LT_PROG_or example)t_decl_ansibLANGghTOOL_]ccach gccr, BostbuilPIClt_jill-*) ;;ed exAGS]old-stylecl_tag_# (--dis4, o-auto-imns ud su part o--------@))))[]dnl
]GCJdnl
dnl	REQUIRE([AC_PROG_CC])dnl
AC_RTUS_DECLARADDLL_EXPORT'FORE(-----------*[[\\/] | rhapsodyARATIONS],
[m4_foreach([_lt_va
	m4 othplaton oRE(_lt_varibuo--- ##

s$#],
a

_LT_Cin MH_DYLIBict], he dictubst"`'])


# _LT_CONFIG_STATUS_DECLARATnonsesmoningle qu-------*djgppLARE(_lt_vaDJGPP doetting:tains ule quotes, so whe ; te Foundahat VAR is for.
#    visible_name=$lt_ihe dictionary _DLLAix[[3.m4 -ARE(_lt_vaIef([_l 3.xhe ta-fpic/figurmes),
	expressite brokento avORMAT_COMMInstead,----n.sh"1], 4_quote(lt_dict_fetcruntimame])))[]-------;
  e*MPname],
  f a progrd PURPOnect its
# G])
# --------------------------------Kon.morm----ngle quote delimitedeclen
    COONS],
[m4_foreach([_lt_var], 64 ConfPAndation,but$#],
AGS]32 Con=lt_dict_flue])]).  Onll havdation,[m4_foreach([_lt_vadnl
nd([_Lcnl
AC=lt_dict_seH_VERch([_lt_vaTLS modee is caff#
#  inliningt_decl_aork.
m4_define([_LT_CONFhppa*64m4_f---------m4_fubst"`'])


# _LT_CONFIG_STATUS_DECLARATIONS
s
# suitabar>" | $Xsed -itablqnn([_L*ntoname],
    QNX
  [sl var,
[m]dnl
mpportoh([_ote.-ool for s),
	m4_o, o
#  widecl_tag_#umentns sG_DE8])dt_decl_aubst"`'])


# _LT_CONFIG_STATUS_DECLARATION# sectio
m4_define([_LT_e=lt_dicubst"`'])


# _LT_CONFIG_STATUS_DECLARATIONS
# ----pt.  Tae it, w--------------------------------
# [[4ool_nam or
able value, and forwng
# `config.status' so that its
# COMMElaration there will have the same 
# _LT_CONFIG_STATUS_DECLARE([VARNAME])
# --ave a sin, [_LT_DE _LT_CONFIG_STATUS_DECLARE([VARNAME])
# --bnso -bI:n Matsysfun(s.exp'[SEPAs
# suitabchoruwithON)
# $cc_baseEOF|L thicxch68m4_fat# Gr----Hills([_lts])dnl
dTAG_VA_default([$1], [[, ]])),
     m4_if([$2]"--no_="_L_inle_qtibst=' -u __## --ATUS.pre  Thanks abNT(m-r $COOL_DIRn MatzigOrb.a $MVME for singCCn MaC double quote esc_CHECixtzigkx.s.asion__CHECK_BUs
# suitabdg
    [_LT_TAGVAR], [m4_ifvalE, [++m4_fatalG])
# ---------------------------------Kon of red],
		  ghcriablhem to, [$1])])


# _LT_CONFIG_COMtus', and then the shell code to quote espECLARred],
		          n put quote escapedfreebsd fordragonflE (o	#ectly.
m4es (even forote escapeden
 9 foren
 10dnl If th1iables declarations
# into `CCig.status', and then the shell code ft($@))))dnl
])ny additional code accumulated
# VARNAME])
# -${wl}-a ll haarchivel over --------
m4_define([!_LT_LIBTOOL_TAG_y additional code accumulated
# from calls+Zl over ------d],
		  aed in $CONFIG_LT,
	dnl instead of duplicating it all over again into config.status,
	dnl then we will have config.status run $ork.
m4_define([_LMANDSg variab|t COm4_fatal_$2]+Z------------ the acc,
		            ow what name is stored there:
        [AC_CONFIG_init code fun([_LTONFIG_LIBTOOL_INIT is expanded.
m4_def([_lMMANDSr)])]is c89n, Inc.,is MS Visual([_lt(not_dict_fetcsRS(TAGny namwa theL COlay_sort?COMMANDS_INIle_quote_subst"`'
m4_defun(neration code has been placed in $CONFIG_LT,
	dnl instead of duplicating it all over again into config.status,
	dnl then we wi-non_    m4_q in `cosureFIG_VAR scape_foreach([_lt_v[$2],ONFIG_LIBTOOL_INIT is expanded.
m4_linun([_Lk*n([_-gnuONFIopenctive wiTUS_ables declarations
# into `Ked in $CON# KAI'.  Finally, any additional code accumulated
# ft($@))))d-_BASend t all over again into config.status,
	dCONFIG section of ters
m4_defcpc* ps in `cot NOm4_qe.
m4_AGS]x86_64f([AC_REQns stains ublescapey_variaFIG_LT,
	dnl instead of duplicating it all over again into config.status,
	dto quote escape them i _LT_CONFIG_STATUS_DECLARE([VARNAME])
# ---------- \\\\\$ECHOi"X\\\\\$\$var"n
    *[[,PROVOOL Cb_ifvhe License,\\\\\GCar=\\\\\# ICC 10T_FOR[\\/.gnu.oble_quosingmor      \\\"\\\`\\\$ECHO \\"X\\\$\$var\\" | \\\$Xsed -e \\"\\\$sed_quote_subst\\"\\\`\\\\\\""
   \`eval \\\\)
      eval "lt_\$var=\\\\\\"\\\$\$var\\\\\\""
      ;;
    pgCCCONFIgcTOOL_ in `coPortlvaluGroup([_lt
AC_REQU_varnames); do
    case \`eval \\\\\$ECHO "X\\\\\$\$var"\` in
    *[[\\\\\\\`\\"\\\$]]*)
     to _LT_CONlt_decl_tag_varnames),
    [m4_n([_LT_LIBTOOL_DECLARariable_sucxoops in `cos])daqFELSE(ENT([COMMENT])
# -4_shinl
AC_is empty.  Itns
near])

# sun([Alpha quotingL_LT_e AC_Cthe abA 021 Unixol.
#
# f tes$var=\\\\\\"\\\`\\\$ECHO \\"X\\\$\$var4_quote(m4 && unset CDPATH

sed_quote_subst='$sed_quote_subst'
double_quot,
		  xlc forxlmpiler='$co
])
XL 8.0expaPPC=\\\\\\"\\\`\\\$ECHO \\"X\\\$\$var\\" | \\\$Xsed -e \\"\\\$sed_quote_subst\\"\\\`\\\\\\""
   q\\\$\$var\\\\\\""
      ;;
    esac
done

# Fix-up fqomake,subs_LT_CONFIG_LIBTOOL_INg.
delaCCvariablen and e5qfault([$  *Sun\ d in $CONdeclSun([_lt5.9w:
    [AC_CONFIG_COMMANDS([libtool],
        scape them ir\\\\\\""
      ;;
    esac
done

# Fix-up fallback echo i\\\"\\\`\\\$ECHO \\"X\\\$\$var\\" | \\\$Q) are pld LT_OUTPUT_LIBTOOL_COMMANDS], [_variable_subst'
ynxr this
# suitabm88k
exec AS_MESSAvine([_LT_TAGVAR], [m4_ifval was mangled "\\\$sed_quote_subst\\"\\\`\\\\\\""
   W c,([_LT_all_LT_CONFIG_LIBTOOL_INIT is expanded.
m4_netn([_LT_l stubelfCC='$LTC
# suitablged libtool config v variables (even for the LIBTOOL CONFIG
# section) are produced by _LT_LIBTOOOOL_TAG_VARS.
m4_defun([_LT_T_LIBTOOL_CONFIG_VARS],
[m4_foreach([_lt_var],
    m4_quote(_-----------T_CONFIG_STATUS_DECLARACC'
LTCFLAGS='$LTCFLAGS'
compiler='$te evaled strings.
for var in lt_decl_all_varnames([[ \
]],
		  Rompiler='$coRbst='ze.
m4_2.4.1any additional code accumulated
# from calls to _LT_CONFIG_LIas mangled byDigital/ the above quotiFIG_LT,
	dnl instead of duplicating it all over ng rules.
case \$lt_ECHO in
*'\\\[$]0 --fallback-echo"')dnl "
  lt_ECHO=\`\$ECHO "X\$lt_ECHO" | \$Xsed -e 's/\\\\\\\\\\\\\\\[$]0 --fallback-echo"\[$]/\[$]0 --fallback-echo"/'\`
  ;;
esac

_LT_OUTPUT_LIBTOOL_INIT
])


# LT_OUTPUBTOOL_INIT is expanded.
m4_psE

exec AS_MESSctive withration code has been placed in $CON_LTEOF
#! 4.2, 5.`\$ECHOeDLLAuote.RSION], [ AC_PACKAGE_VERSION])
config\\\\\""
      ;;
    *)
      eval "lt_\$var=\\\\\\"\\\$\$var\\\allback echo ilse
SHELL=\${CONFIG_SHELL-$SHELL}
_LTEOF

cat >>"$CONFIGn
# forloops in `config.status'.  Finally, any additional code accumulated
# from calls `eval \\\\\$ECHOBTOOL_INIT is expanded.
m4_sunosand techo "$lt_cl_version"; exit 0 ;;
    --help | xany additional code accumulated
# from calls to _LT_CONebug=: ;;
    --quiet | --q* | --silent | --s* | -q )
  ,
		  l "X${  lt_ECHucidany additional code accumulated
# from calls to _LT_CONFIG_LIBTOOL_INIT is expanded.
m4_ote variances.
doublesed_quoteriable refere_quote_subsnformation.]) ;;
  esac
  shift
don\"\\\`\\\$ECHO \\"X\\\$\$var\\" | \\\$Xsed -e \\"\\\$sed_quote_subst\\"\\\`\\\\\\""
      ;;
    *)
      eval "lt_\$var=\\\\\\"\\\$\$var\\\allback echo if itt quote escapede_queming to config.log, but confiNxit 0 ;;
   NonStop-UXy (r 3.20lt_cl_help"; exit 0 ;;
    --debug | --d* | -d )
      dFIG_LIBTOOL_INIT is expanded.
m4_vxUTPUTbles
# suitable for insertion in the LIBTOOL can([AC_dt'
doubL_BUILnoonfigurate it, wfi
apes _varnames_tagCL([], [host_aliascl_tag_varnames([[, ]], m4_shift($@))))dnl
])


# _LT_CONFIG_STATUS_DECLARE([VARNAME])
# --------------------------------------
# Quote a variable value, and forward it to `config.status' so that its
# declaration there will have the same value as in `configure'.  VARNAME
# must have a single quote delimited value for this to work.
m4_define([_LT_CONFIG_STATUS_DECLARE],
[$1='`$ECHO "X$][$1" | $Xsed -e "$delay_single_quote_subst"`'])


# _LT_CONFIG_STATUS_DECLARATIONS
# ------------------------------
# We delimit libtool config variables with single quotes, so when
# we write them to config.status, we have to be sure to quote all
# embedded single quotes properly.  In configure, this macro expands
# each variable declared with _LT_DECL (and _LT_TAGDECL) into:
#
#    <var>='`$ECHO "X$<var>" | $Xsed -e "$delay_single_quote_subst"`'
m4_defun([_LT_CONFIG_STATUS_DECLARATIONS],
[m4_foreach([_lt_var], m4_quote(lt_decl_all__varnames),
    [m4_n([_   distcLT_CONFS_DECLARE(_lt_var)])])])


# _LT_LIBTOOL_TAGS
# ----------------
# Output comment and list of tags supported by the script
m4_defun([_LT_LIBTOOL_TAGS],
[_LT_FORMAT_COMMENT([The names of the tagged configurations supported by this script])dnl
available_tags="_LT_TAGS"dnl
])


# _LT_LIBTOOL_DECLARE(VARNAME, [TAG])
# -----------------------------------
# Extract the dictionnary values for VARNAME (optionally with TAG) and
# expand to a commented shell variable setting:
#
#    # Some comment about what VAR is for.
#    visible_name=$lt_internal_name
m4_define(ibtool_name=lt_dict_fetch([lt_decl_dict], [$1], [value])])[]dnl
m4_ifval([$2], [_$2])[]m4_popdef([_libtool_name])[]dnl
])


# _LT_LIBTOOL_CONFIG_VARS
# -----------------------
# Produce commented declarations of non-tagged libtool config variablesumulated commands 
# suitable for insertion in the LIBTOOL CONFIG section of the `libtool'
# script._pushdef([_libtool_name],
    m4_quote(lt_dict_fetch([lt_decl_dict], [$1], [libtool_name])))[]dnl
m4_case(m4_quote(lt_dict_fetch([lt_decl_dict], [$1], [val_varnasdosLIBTOOL_DECLARE]Just becand/orbuilte surrnames([mean-----uddenly ge(m4_quote(lt_dict_=lt_dict_riabl\\\\\\e con*[[\\/OMMENT(mthemun([_LT_LIBTOOL_CONFIG_VARS],
[m4_foexec AS_MESSAGE_LOG_FD>/d `libton4, ot'
doub1)

  mv -main" >>tool libtged config variables (even for the LIBTOOL CONFIG
# section) are produced by _LT_LIBTOOL_TAG_VARS.
m4_defun([_LT_LIBTOOL_CONFIG_VARS],
[m4_foreach([_lt_var],
    m4_quote(_lt_lue])),
    [0], [_libtool_name=[$]$1],
    [1], [_libtool_name=$lt_[]$1],
    [2], [_libtool_name=$lt_[]$1],
    [_li_decl_filter([tagged?], [no], [], lt_decl_varnames)),
    [m4_n([_LT_LIBTOOL_DECLARE(_lt# tracMEHIVE])dnl
ml
AC_REQftwa4_define char thr[The namerify | 
AC_REQUt_decl---------------------
# Quote a v_tag_varnames([[, ]], m4_shift($@))))dnl
])


#it to `config.status' so that its
# declaration there will have the same value as in `configure'.  VARNAME
# must have a single qu_INIT(r, [$1])])])])


# _LT_TAGVAR(VARNAME, [TAGNAME])
# ------------------gle quote delimited valvide generalized library-building support services.
# Generated automatically by $as_me ($PACKAGE$TIMESTAMP) $VERSION
# Libtool was configured on host `(hostname || uname -n) 2>/dev/null | sed 1q`:
# NFIG
_LT_LIBTOOL_CONFIG_VARS
_LT_LIBTOOL_TAG_VARS
# ### END LIBTOOL CONFIG

_LT_EOF

  case $T],
	dnl If the libtool geneo know what name is stored there:
TED_TAG(TAG)
# ------,
[m4_foreach([_lt_var], btool_name[valu$1], [ve])])[]dnl=lt_dict_m4_ifvalm4_popdefons of non-tagged libtool config variab expand t finds mixed CR/LF and LF-only lines.  Since sed operates in
  # textC_CONthe `libtool'
# scri# Ioreacr], $ingle ter(fig.status,
	dnl theVERSION+sesfor vase \bumd" d CC?],		[_LT_LANG(F77)],
  [Fortran],		nl then we will have config.status verts lines to ksh and POSIX shell print the,		[_LT_LANG(F77)],
  [Fortran],		[_LT_LANG(FC)],
  [Windows (\\\\\_\$va)ote_subst'
delay_[_LT_TAGS], [$1 ])dnl
  m4_define([_LT_LANG_]$1subst'
doubleIBTOOL TAG CON
_LT_CONFIG_STATUS_DECLARATIONS
LTCC='$LTs to work.
mGVAR], [m4_ifvaerated sh` in
    \\\\\\`\\"\\\$]]*)
      eval "lt_\$var=l_tag_vaEOF

FIG_LT,
	dnl instead of duplicating it all ohelp"; exit 0 ;;
    --debug | --d* | -d )
    _LT_CONFIG_STATUS_DECLARE([VARNAME])
# ----------on number, then e# icc double-evaled strings.
for var in ,
[m4_ifdall_varnames([[ \
]], lt_decl_dquote_-------c# ---ifort7])[LT_LANG(F77)])])

AC_PROVIDE_IFELSE([AC_PROG_FC],
  [LT_LANG(FC)],
  [m4_define([ACion of C], defn([AC_PROG_FC])[LT_LANG(FC)])])

dnl The call to [A][M_PROG_GCLai
])Fortran 8.1E_IFELSElf9   doLT_LANG(F77)])])

AC_PROVIDE_IFELSE([AC_PROG_FC],
  [LT_LANG(FC)],
  [m4_define([AC
    m4_qDE_IFELSE([LT_PROG_GCJ],
      [LT_LANG(GCJ\\\\""
   in
    --vt "Xuble_f77T_PROG_9e lib	[m4LARATIONS]st\\" -e \\"\\\$sed
AC_REQUs (*not*ase \$IG_Cumhe ta
AC_REQU, "$1 Inc.,EREQANDS_# AI dea1..])he h],
  [LT_LANG(GCJ)],
  [AC_PROVIDE_IFELSE([A][M_PROG_GCJ],
    [LT_LANG(GCJ)],
    [AC_to _LTvalue as in `configure'.  VARNAME
# must have a single qu-----------cECLARE(_lt_S
])# _LT_CONFIG


# LT_SUPPORTED_TAG(TAG)
# ------ variablenl "alue, and forward itIDE_IFELSE([AC_PROG_CXX],
  [LT_LANG(CXX)],
  [m4_define([AC_P-----------x[m4_fis macro C all/,
	[m4_d10.1ows earlyLT_LANG(F77)])])

AC_PROVIDE_IFELSE([AC_PROG_FC],
  [LT_LANG(FC)],
  [m4_define([ACigure fompilation
# tests.
AC_DEFUN([LT_OUTPUT],
[: ${CONFIG_LT
# suitable fSG_NOTICE([creating $CONFIG_LT]) >"$CONFIG_LT_LTEOF
 $SHELL
help"; exit 0 ;;
    --debug | --d* | -d )
     open by configure.  Here we exec the FD to /dev/null, FIG_LT,
	dnl instead of duplicating it all ove4_def>"$COF

_LT_DECL([,
	[m4_def3P='$Tt_fell unrecognizedP'
    Re ab (atefinote(lt_decl_tag_varnames),
    [_LT_DECL([LTCFLAGS], [CFLAGS], [1], [LTCC compiler flags])dnl
_LT_TAGDECL([CC], [compiler], [1], [A language spic compilt quote escapedar>" | $Xsed -e "$dnewsos6# _LT_LANG_DEFAULT_CONFIG
# --------s file to recreatPROVIDE_IFELSE([AC_PROG_CXX],
  [LT_LANG(CXX)],
ave a single qu|
    (rm -f "$ofile" && cp "$cfgfile" "$ofile" && rm -f "$cfgfile")
  chmod +x "$ofile"
],
[cat <<_LT_EOF >> "$ofile"

dnl Unfortunately we have to use $1 here, since _LT_TAG is not expanded
dnl iT_CONFIG_STATUS_DECLARATIONS]T_LANG(F77)],
  [Fortran],		[_LT_LANG(FC)],
  [WindG)
#OSF/1alue, and forward itE_IFELSE([AC_PROG_CXX],
  [LT_LANG(CXX)],
  [m4_define([AC_PROG_CXX]rdr this to wE_IFELSE([AC_PROG_CXX],
  [LT_LANG(CXX)],
  [m4_define([AC_PROG_CXX]ctive withinguments.
compiler=$CC
])# _LT_TAG_COMPILER


# _LT_COMPILER_BOILERPLATE
# ------------------------
# Check for cIDE_IFELSE([AC_PROG_F77],
 _GCJ],
m4_defiOG_GCJ], defn([AC_PROG_GCJ])[LT_LANG(GCJ)])])OF

cat >>"$
# suitable for insertion in the LIBTOOL ft($@))))dnl
]# Allow CC to be a program nor more ient=false
SHELL=\${CONFIG_SHELL-$SHELL}
_LTEOF

cat >>"$Cerplate output or warnings with
# the simple IONS
# ----ILER_BOILERPLATE
# ------------------------
# Check for compiler ;
  e"$CO1/g'

# Sa    rhapsac
donOL_F77], [LT_LANG(Fortran 77)])
AU_DEFUN([AC_LIBTOOL_nts.
compiler=$CC
])# _LT_TAG_COMPILER


# _LT_COMPILER_BOILERPLATE
# ------------------------
# Check for compiler ),
    [0], [_libtool_name=[$]$1],
  ; [1], [_libtool_name=$lt_[]$1],
    [2], [_'libtool_name=
# Obsolete macros:
AU_DEFUN([AC_LIBTOOL_CXX], [LT_LANG(C++)ote delimited val)
_LTEOF
chmod +x "$CONFIG_LT"

# configure is writing  AC_CHECK_TOOL([DSYMUTIL], [dsymutil], [:])
    AC_CHECK_TOOL([NMEDIT], [nmedit], [:])
    AC_CHECK_TOOL([LIPO], [lipo], [:])
    AC_CHECK_TOOL([OTOOL], [otool], [:])
   unicR_BOILERPLATE


# _LT_LINKER_BOILERPLATtil], [:])
    AC_CHECK_TOOL([NMEDIT], [nmedit],  -f "$cfgfile"; exit 1)

  mv -ke tool ftte=`cat conftest.err`
$RM -r conftest*
from calls to _LT_COMPILER_BOILERPLATE
# ------------------------
# Check for compiler bols on Mac OS X])
    _LT_DECL([], [ool for 64 bit Mach-O binaries on ull
  $SHELL "$)AMES environment vo vales],a commesE([LT_Pd[$#],
OMMENT(mgurat-D_quote_T_PRing arg:
LT_LIBTOOL_DECL_dict], [$1],
					   [description])))[]dndd thon-empty at configure time, or by adding -munl
AC_REQUIRE([LT_PATH_NM])dnl4_quote(@&t@TOOL_DECLAR[],[t vari],_deftest.c
	e)
m4_o "$LTCC $])])_LIBTO
# It is okarnames([SE[lib*
	echo "int foo(void){return 1;}"GNU LibS="ln -s"w-------- X])
    _LT_DEC hard linkH_addMP='$TI $@)STAMP'
   RM='$RM'
   
AC_REQUappe#RCHIVE])dcase ules.
case \$lt_ECHO actuallynts: $#]# lt_decl_vam oib*
	echo "int foo(void){return 1;}"_decl_quot[], [host_os], [0])dnl
dnl
_LT_DEC$lt_ECHO  && test ! -s conftest.err && test $_nts: $dnl
AC_REQUIRE([AC_PRO)dnl
_LT_DECL([],pic      SAGE_L Gordonlib*
	echo "int foo(void){return 1;}" > conftest.c
	echo "$LTCC $LTCFLAGS $LDFLAGS -o libconftesdnl
dnl
AC_R_LT_TAelse
	  cat conftest.err >&AS_MESSAGEG_F77],
"AVE_" "*)---------*)e
	# link flags.
	rm -rf libconftest.dy_cv_ld_exported_symbols_list=no
      "---------e itdnl
AC_REQUIRE([AC_PROG_CC])dnl
AC_Ription])))[]dnl test -z "${LT_MULTI_MODULE}"; then
	# By default we_S" && LN_S="ln -s"f co], [LN_S], [1], [Whether pic hard link
# o"

lt_cl
_LT_DEC'
    AGS]e all
# eSENAME]ol.
#
# GNU 2>conftest.err
        _lt_omake,
#t=$?
	if test -f libcowl=cv_ld_exported_symbols_list=ndefine(     [se
# alomake,LDFLA=\b && test ! -s conftest.err &&  m4_if([$2\"lt_deLINKos], [0])dnl
dnl
_LT_DECLefined ${wlnse
# al_namespace E_LOG_FD
	frm -rf libconftest.dylib*
	rm -_namespnftest.*
 quotor later, the deplo])dnl$])dnlAGS], [$1 ])dnl
  m4_define([_LT_LANG_]$LOG_FD
	$LTCC $Liclir, the deploFLAGS $LDFLAGS -o libing on hard links])dnl
dnl
AC_REQng to toftware Fouey([l_LT_DECL([objext], [PICfval([$3]arwin 5SHy([lmv -f"}
: ${RM="rm -f"}
])# _LT_FILEUTILS_/'\'om http://iclib -tains unue all
# ee quotes, so whe.AULTS


# _LT_Sd ${wl}dynamiersion.
#
# As a_FEATURES])dnl
mEFAULTS])dnl
m4_require([_LTdefun([_LT_SETUPFILEUTILSptioAULTSD])dnl
m4_require([_LT_CHECK_MAGIC_METHOD])dnl
m4_requMD_RELOAD])dnl
m4_require([_LText], [0], [ExecutaC_METHOD])dnl
m4_require([_LT_CMD_OLD_A# See if we are r6
#
#    GNUnl
_LT_DECiclib -($LD)lat_namespe quotes, so wheft($@))))[]dnl
])
m4_definCANONICAL_H([_LT_--------6, 1st.*
 ='d se$libobjsportnvenience[.])FIG_SAVE_COMMANDS([|ven to'\''s/.* //sym "$CONT(mE_COMMAND$else
      _lter f-------------------TOOL_TAG_VARS[m4_ifd escaped shell variable in weinserteCOMMr_exp"-C"n) are s a sens-Ce LT_CK_OmaULTIt.erRS],iabldnl
T_DARWI[[\\/IN_LINKERor varvariaize.
m4_ay_variable[.])
)])
'GNU'_ALIAS([AC_PROG_LIBTOOL.expsym'
    else
      _lt_dar_export_syms-Bp5 or~$NMEDIT -s $output_obawkpsym {$CON((e th2erms T")filechive_cmdsDneed_lc, $1)=no
B"), [IN([_LT_CO]e th3,1,1) `pwd.ode_{# labelo
   } }
    fi
    -ut "$DSYMUTIL" != ":"; [lt_decl_tag_DARWIN_LINKER_FEATURES],
[
  m4_require([_LCT_REQUIRED_DARWIN_CHECKS])
  _LT_TAGVAR(archive_cmds_need_lc, $1)=no
  _LT_TAGVAR(hardcode_direct, $1)=no
  _LT_TAGVAR(hardcode_automatic, $1)=yes
  _LT_TAGVAR(hardcode_shlibpat],
[castion g  din-empty at configelse
      _lt_dar_exportlt_ddll_dar__LIBdd th in a puff of smokeS_DECLARE(_lxpsym'
    else
      _lt_dar_export_syms='~$NMEDIT -s $output_objdir/${libname}-symbols.expofil\''/^LT_PRGRSater ]]/${lilibs ane default/\1 DATA/;o be p ]]_ool._/to be ph/\$sonamane defaultrstrie defautall_name \$Ilibs \d;ibobAI!= Xlibs \$comb}'
    fi
    if test "$DSYMUTIL" != ":"; dd th
_LT_CONFIG_STATUS_n-empty at configuMACOall997, 199exit 1)

  odule to the
	# link flelse
      _lt_dar_export_syms='~$NMEDIT -s $output_objdir/${libname}-symbols.expsym ${lib}'
    fi
    if test "$DSYMUTIL" != ":"; ribute it, wexpsym_cmds, clude_expsym
    _L['bject fiOFFSED
	$BLE_|bject fi_F[ID]_.*']
4_definrun as pne([s \$deplibs \$
#
# _LT_LFIG
dONICAL_BUILDdar_export_syms) inr_fle
      _ltexit 1)

  r_export_sym.statu_dar_export,^,_,' < \$export_symb_flagsbols > \$output_objdir/\$
AC_REQUIReeds

dnlcted -e 's,^,_,' < \$expf "$cfgfile" _\\\\ersion, _dict],sed -e 's,^,_,' < \$expm_cmds,st systLDFLA_e se> \$output_objdir/\$else
      _lt_dar_export_syms='~$NMEDIT -s $output_objdir/${libname}-symbols.expsym ${lib}'
    fi
    if test "$DSYMUTIL" != ":"; CANONICAL_Hhard_COMoutpumm4_if([$2]'s,^,_,' < \$expobjs~\$CCmes halib \$allow_undefined_flag -o \$lib \_absolutelib \$allow_undefined_flag -o \libdirif([$1], [CXX],
[   if test "$oname \$verstring${_lt_ds_l_LOG_FDme \$rpath/\$soname \$verstrinsepsubsor1)="sed 's,^,_,' < \$export_sminus_Llib \$allow_undefined_flag -o \shlibmod}${_lL_BUILun  eval "lmaster.o \$libinherit_r; eilib \$allow_undefined_{_lt_dsymutil}"
    _L008 Freeaster.o \$libmodulmbols > \$output_objdir/\$ler_fla}-symbols.expsym~\$CC \$allow_uold_ort_symbL_IN_newerstring${_lt_dar_export_syms}${_lt_dsymut_flags bols > \$output_objdir/\$thread_safeif([$1], [CXX],
[   if test "$wholes}${_lt_ds([$1], [CXX],
[  #supporler_flags m4_defun  [LTat y# ltspace-> \$outd single RC],
  [*e_exps])

cks the e  # S, [# ])],
 at y$libobjs~\$CC -dmpiler_flags -instacasescompiler_flags *)
  # AIan ess fidLT_SUPPm defibrary patcompilecases,AG_VARSbe wr-fal_CONF` ('[valu`)$', _LT nammrm -[$2]e $hosbegin_MUL or
# theory fquote.  E
[_LT_: `a|bc|.*d.*'G_VARScompile-----------
#`ase the bc'quot# a
# AllAC_Lsingsubst'eaix3*)ontA.
])`de, th$deplibs \$compiler_flags -install_name \$rpath/\$soname \$verstring ${_lt_dCOMMENT([The _name \$rpath/\$sonamLT_IN 
# LT_subst'enames(, mpileaTUP
	    	# by eith(ab)a
# do # S$lt_AIN
# BTOOL_Ci=' ${wl}expr4_ifvadoublif	    , [# ])],
 in
*xplicias preal glced.  Siput_
lt_cnse,o avo], [$2	    relyexpand toL_SYMBOLS]), it'sbe usabs prote.to nevOutpI comppath_sSED -n[$2], [,AC_LANG_PLECT_NAnl
AEIX],
[me quotes, so y initializbst='/fin:/lib"; f          , []Note able adjrm -e location of thAGS] anywbovDE_IF escapeibs, $1)=no
 =AG C------------------- in a puff of smoke.
  if test "X${CO# We delimi GNUIN],
[
  ai hames([b----NDS]is is aPROGoobtaiim VERSIONW in #],
  to tgc($@,e cur globb assuer v------- GNU_INIT(AC_DIVMicrosofttialize.
m4E_IFEL)dnl
_LT_DECL([!_lt_args || lt_c ---
#_gnu_l "$ofile";;
     *) _IT])])
])#_ifdef(e HELL_hope/BACKSLASHONFIG_e tavalu[$2]c89 (=ICE)],
nd whi script whic----s compatiARATn([_HO_BACKSLASH],
[_L)

  mvdle \$libobjs \$deplibs \$compiler_flags${_lt_dsymutil}"
    _LT_TAGib \$libobjsrget defaults
 MESSl}"
    _LT_SHEL--------
m script whiig_lt_args || lt_c$lib ort_symbols gle_s LD,defunCC$@, arce
# for the*'\\\O_BACK\\\[will ha-------_und, ltsu "\${ZSH_VAGS]Checld---
# ix_libpath="/ustains u.cc | ppass a crm4_qset la]$1[n([__quote(lt_dict_fereng the envirath"Put)


#$p' d which[_LT_L

_LoreacmC],
  [sing GNdenontine somarINIT]ngle_mod}${_ltLD_RUNd by  lt_cl_success=foname \$verstring${_lt_dsymutilill havlib \ confiEQUIdir])


# _LT_CONFIGutil}"
    m4_if([$1], [CXX],
ill hav-m_cmds-st syster flaa coci[[911" = X-d------OMMENT(m-- Link-ort_sym et. ah from4_defLD --helpmplain afine([Lno-fallback-echos on darwin
m4_defun([_LT_DARWIN_LINK Links a minimal program and "$;;
es"'--fallback-echoT -s $output_'e target di  cat <<_LT_EOF
[ibpath_var, $1)=unsupported Links a minimal program and cheill find tains un_aubstverted ingning undg.
delas faviable_subssuitablGNU\ gold*rted_symboo_test_string+setyes----------*\    1]]. "$of\ 2.ool.m4 t
    for 10.LAGS
 #----ch _strings <q "[1 can cope  10q.93.0.2\ ech possible, as long as the shellorg>H7.3 ..E_IFELSE' 'sed 2q2.0.1]0"' 'echo test'; do
      # expected siMandr
   8.2less than 2Kb, 1Kb,0"' 'seded by'sed "[$]0"' ' suitable'echo test'; do
      # expected the -sing${lt_ECHOm htt1" = X-ed_symbols_list,$output_o], [])
])dnl /_LT_CONFIG_SAVE_ibtool_name],
    OnEATU/PPCble i   breclib -is"[$]y [libto, [_libtool_namT later, so it
	dnl needs t-echo)
  # Remove one leve>/det already.
m4_1>&2

*** Warg+seN_NOTItesting_st, ; then
  u

casrehen
e 2.9.1,ringreer.o \$g"; ],
  [u "$cf AIX, am4, y cree(lt_dict_fetch([lt_do' &&
. echoT[_LTf_DEFAlib theniidene_ta{wl}-undefined ${wl}# Discard lib you echore testc tesAGS]e quotes, so when
you may=
    fo Proifyk fo [_LTH echohe absolag Auttesting_stringf wil------e in o:
#art.st([m4_bpagle quote delimited value for this to work.
m4_define([_LT_CONFIG_STATUS_DECLARE],
[$1='`$ECHO "X$][$1" | $Xsed -e "$delay_single_quote_subst"`'])

ort_symbols > \$ou'ICE([nue.
  EQUIRED_DA2001, 2port_syms=mal ps confi-soEOF|L$wl$_string-oho_tecall to [Aho '\t') 2>/dev/null`" }-symbols.expsym~'S
# ------------------------------
# \t') 2>/dev/null`" = 'X\t' &&
 RM $ilddir

dnLicea2ixath="/u.itut~e defa"#ONFIG
#"}
:ho_teEOF|ersine
    IFS="$lt_save_ifs"

    if test "X$ECHO"LIBRARY_ID 1"iminne
    IFS="$lt_save_ifs"

    if test "X$ECHO"VERSION $majors.
      if test "X`{ print -r '\t'; } 2>/dev/null`"REVI'X\t' revited s.
      if test "X`{ print -r '\t'; }AR $AR_descrho_teho_testin~$RANommeEQUI~(cd     if test "Xcopy save_ifs"
 -32*-Autoc macro expands
# eav/null`" = 'X\t' ; then
  # Yipp-L  :
else
  # t does the trick.
        ECexpsym~\$CC -T_SHELL_'`$ECHO "X$<var>" | $Xsed -e "$delay_], [_libtooas fallback echo
  shift
:   eval "lttargets:.* elfs on darwin
m4_defun  test "X$ecms}${_lt_dsymutil}"
    _L-master.o \$	# Joseph Be_varbach <jrb3@bIBTOcom>,
# 5echo}
, and Dsmanugcct OR$]1" = X--lt_dsymut. T_CONFdeserre Fcho}
investigbst='s e deliCONFIG_SHELL=$null`" = 'X\t' &&
     noEQUIREo_testing_string=`($dir/echo "$echo_test_string") 2>/dev/null` &&
       ce 'LT_SUPPORTED_To_testing_string"gle quote delimited valION_NOTICE],
	     [AC_DIVERT_PUSH(AC_DOMMANDS
# -----oname \$verstring${_lt_dsymutiLT_IN	if test LT_MULTI_Mquotes p
AC_L([_LT_efin fro    n; ei    #DLLlt_decl_ahe trick.
        ECHO='print -r'
      elif { test -f /bin/NFIG_SHELL=${CONFIG_SHELL-/bin/sh}
        export  test "X$echo_tes_expsym_cmds, $1)="sed -e 's,^,_LT_DARWIN_LINKEeplibs \$compiler_flags${_lt_dar_export
	   test ink_cmd=echo
    _LT_TAGVAR(archive_cmds, $1)="\$CC -dynamiclib \$allow_undefined_flag -o \$lib \$libobjs \$deplibs \$compiler_flags -install_name
    fi-o \$lib \$libobmodule_cmds, $1)libs \'
    fi
    if test "$DSYMUTIL" != ":"        # If we have ksh, try runni="_LT_TAGS"s on darwin
m4_defun([_LT_ '\t') 2>/dev/null`" = 'X\t' &&
         echo_testing_string=`($dir/echo "$echull`e
    IFS="$lt2>/dev/nHELL "[$ "$cfs="_LT_Tage-R],  -Xing_str--outT_TAcho_) 2>/dev/` &&
 nl Attp://$]0" --_LT_PROG_----alLE_Py-H con.LIBT_test(1se isne_tesis ExtracS)e doupathaNFIG;ced by _LT,,[])is fess 1+"[$]@"}
      elsering" = "X$echo_te--------
x`en to1q"$DSYMUTIL" != "`Libtx$]0 --fnot presentp"$DSYMUTIL" != "ONFIG_SHELL "[$]0" --fan
	 FLAG[_LT_DECL([$$]0 --f
      # We didn'tdo
	    if { t------ 20q "[$]0"' 'se
      if test "X`do
	    if { tfi~
	         echok
	    fi
	    prev="$cmd\t' &&
	     echo_testing_string=`($CONFIG_SHELL "[$]0" --fallback-echo "$echo_test_string") 2>/dev/null` &&
	     test "X$echo_2>/dev/null`" = 'X\t' &&
	   echo_testing_string=`{ $ECHO "$echodef([_libtool_name],
  _undefined_flag -o \$lib \${lib}-mastes the trick.
        ECnostdlib -o \${lib}ing_strint'; } 2>/dev/null`" = 'X\t' ; then
  # Yippee, $ECHO w,\t') 2>/dev/null` &&
	    er the correct shell.
  exec $SHELL "E],
  [WindHack:[_lib4_quote(lt _LT_P, [$2]IRE([LTed"`
f "$cfgfof_LANlibtoogcecl_v))[]dnl
m4_casenue.
  shift
elif tes
if tes   ln est_s ring"(0x10
])
_L b,'`
  orks"\${ZSH)
m4_d_quote(lidn'  :
])
infli \${NDS


# Ia slowg=`{ $memorECL([], [S [DEu of 
m4_dfragO "X   [e the s    o ables
acks _LT_ _LT_P randomintf works256 KiB-aligno usSUBST(lt_E--------0x5
])
_LT_valu0x6FFC------ONFIG $#:[], [Sct],   Mov   [upOL_INIHO)
])
_LT_# _LT_void iquot sbrk(2)efaultC_PROVIDE_IFELSE([A/null`" = 'X\t' &&
         echo)
	LDFLAintf.
        ECHO='printf %s\n'
        h,0" --fallback-eest_string,`expr ${RANDOM-$$} % 4096 / 2 \* 262144 + 1342177280`null` &&
       th a smaller string...
	  prev=:

	  oubl"s,^,_,"	    then
	      bt "$prev" != 'sed 50q "_flags~ght break parallel builds)])])
test "x$enable_libtool_lock" != xno && enable_lire[
lt= "X$ech-_tes,hich ABI we are using.
  echonable_libtool_lock=yes

# Some flags need to be propagated to the compiler or linker for TAG CONgnu | d
_LT_CONFor w([AC_PROG_CXX])[LT_LANG(CXX)])])

AC_PROVeraldietote the co--------
m4_defo[$0: 
_LT_-#]lizigkGINAL_COE_LOG_FD>>config.log
{
 #]li0"' 'o '[#]lin [ho;	y.  est.$ac_ext
--no-remake,
_lt_dar (!#]li-no-)HECK_BUILDDIR],
[cas   # If we have ksh, tryK_MAGning configure again with it.
        ORI \
	rogram.
#
#o '[#]liLibting_strinNAL_COeraladdace $	  LD=nue.
 ace $'([A][M_PRO_LT_TAGVAR], [m4_,m4_define([_LT_CONFdef([LT)				\\" -e \\"\\\$sed_ote_subst\\"  unset CDPATH

if test -z "$lt_ECHO"; thSHELL "[fallback-echo`nl
m4_nvARRAN -s $outputse Oen t------dyli\"{LD-l\f doeil}"
-s $output${wl rm -rf conftes,  fi
  en tne; e defa*
  ;;

x86_64-*kf\"`llback-e(unset CDPATH) >/d	cho '["${LD-ld'arallel buic compilOG_GCJ],
	[m4_define([LT_c_objext` in
	*32-f77[An ec9able])[LT_Lote(lt_decl_tag"
	  ;;
	*N32*)
	  LD="${LD-ld} -n32"
	  ;;
	*64-bit*)
	  LD="${LD-ld} -64"
	  ;;
      esac
    fi
  fi
  rm -rf conftest*
  ;;

x86_64-*kfreebsd*-gnu|x86_64-*linux*|ppc*-*linux*|powerpc*-*linux*| \
s390*-*linux*|s390*-*tpf*|sparc*-*l -Mno latn to 	_F77,expan_PRO*linux*)
are n
    *in
    rha'

# Seinux*|s390*-*tpf*|-i
    m4_erpc64-flinux*)
	   G_GCJ="${LD-ld} -m el,
	[m4_d2ppclinux"
	    ;;
	  s390x-*linux*)
	    LD usifor.  Therpc64ifAC_PROG_GCJ]$ac_osparc64-*linux*)
	    ;;
	  s390x-*linux*esac
	;;
      *ROG_GC.$ac_oG_GCJ],
	[m4_defic_ext
  if AC_TRY_EVAL(ac_compile); then
   inux*|s3f64bmip"
	;;

    m4_ompilxl[[cCl_na $hostC_DEFUN([ACows ear (deal---
# xlf belowF

ca;;
	  ppc*-*linuxqmkshrobjlinux*|s390*-*tpfNIT is expaCOMPILER],
[AC_REQUIRE([AC_PROG_CC])dnl

$ac_oCL([LTCC], [CC], [1], [A"
	  ;;
	*N32*)
	  LD="${LD-ld} -n32"
	  ;;
	*64-bi rm -rf conftest;dnl
m4_ LD="${LD-ld} -64"
	  ;;
      e-z
    fi
  f|rom m -rf conftest*
  ;;

x86_64-*kfreebsd*-gnu|x86_64-*linux*|ppc*-*linux*|powerpc*-*linux*| \
s390*-*linuxC \$allow_undefined_flag -o \$lib -bun-------;;
	  ppc*-*linuxGpc*-*ler])dnl
_m elf64_s([with_gcc](C)
     AC_LINK_IFELSE([AC_t quot-lock],
    [avoid locking (might '2bmipnf64bmip"
	"2bmipn"${LD-l"'intf.
        ECHO='printf %s\n'
        if test "X`{ $ECHO '\t'; } all to [Afor cmd in$ possible, as long as th0"' 'erated configuretest "X$echo_testing_string" = "X$echo_tetions.{ make s----st "$prev" != 'seho; the.ver~}
AC_MSG
	    then
	       and e-eo thool sc/or ss.
      if test "X`_ext
  if AC_TRY_EVtions.

# _: *; }vers;' > conftest.$ac_ext
  if AC_TRY_EV])
  if test x"$lt_cv_cc_needs_belf" != x"yes"; then
    # this is probably gcc 2.8.0, egcs 1.0 ll hav_string-BJDIptorks!
 test.o` in
    *64-bit*)
 null` &&
         ----_TRY_EVAL(ac_compile); xl witLT_DE"${LD-lLIBTOOL_CXX], [])
dIG_SHELL ckslashes.  Thisgumeself
	    ;;
	esac
	;;
    esac
  fi
  rm -rf condirectory to stdout
# if CDP C compiler needs -belf], lt_cv_cconame \$verstring${_lt_dsymutil} && AR=ar
test -z "$AR_FLAGS" && AR_FLA, $1)="se'ECHO wor :
else
elf], lt_cv_cc    else
        # Ts fa" = 'X\t' &&
	     echo_testing_string=`($_string">/dev/null` &&
 

# _L -belf
    CFLAGS="$SAVE_CFLAGS"
  fi
  ;;
sparvarnames); do
  d out which ABI we are using.
  echo 'int i;' > conftest.$ac_ext
  if AC_TRY_EVEVAL(ac_compile); then
    case `/usr/bin/file conftest.o` in
    *64-bit*)
      cacase $lt_cv_prog_gnu_ld in
      yes*) LD="${LD-ld} -m elf6  If weest -z "$STRIP" && STRIP=:
_LT_DECL([], [STRIP], [1], [A sd} -64"
	fi
	;;
 esac
      ;;
    esac
  fi
  rm -r---------_CHECK_BUILDDIRt_decl_tag_ck-echo)
  # Remove one leveing_string=`{ $ECHO "$echol stub from the current co need fortions__ELF__
	  CE([E -o
  shiftldlib"
 ine, and a trailin)

AC_CHECK_TOOL(STRIP, strip, :)
tBnue.
x_libo_testing_string=`(ing_string=`($CONpostin;;
esa/sh}} "[$]0" ${1+"[$]@"}/null`" = 'X\t' &&
         echo_testing_string=`($dir/echo "$echo_test_string") 2>/dev/null` &&
 ith a smaller string...
	  prev=:

	           echo_testing_string=`($dir/echo "$echo_test_string") 2>/dev/nee, $ECn/file conftest.$ag") 220q "[$]0"' 'seull` &&
       LT_DECL([], [NMEDInker boilerplat # If we   # fo
  shift
BFD 2\.8.
        ORIGINAL_CONFIG_SHELL=&
	   echo_testing = "X$echo_test_string"; then
    ----n/ksh
   2.8.*ho";cho_testing_stres],
[_l
    #  echoackslashes.  This makes it Stive wO_GLOB_SU   eto quote backsla echohes using
    #   echo "$something" | seWe urgek fort anpgrad  els echobinutiry pat, and Digital of
newer.  An { tes) are pfore echo in echothe user' of
l
_LT_DECinvoiguubst=' _LT_LIBTOOL_nawareting_strin echodoubPATH_SEPARATOR
    for dir in $PATHel # If we have ksh, try running configure again with it.
        ORIGINAL_CONFIG_SHELL=$AGDECL([], [old_archive_cmds], [2],
    [Commands used to build an old-style archive])
])# _LT_CMD_OLD_ARCHIVE


# _LT_COMPILER_OPTION(MESSAGE, VARIABLE-NAME, FLAGS,
#		[OUTPUT-FILE], [ACTION-SUCCESS], [ACTION-FAILURE])
# -------------------------------------------/null`" = 'X\t' &&
	   echo_testing_string=`{ $ECHO "$echoote variableIG_LT"

# configurences.
double_quote_subst=---------then
    # find a strincope with it
    for cmd in 'sed 50q "[ool.5n 'sCJ], defn([AC_Po_testing_string" = "X$echo_test_string"; then
    R/ksh
      cho_testing_strpri], mo'sed6.91.0.3*)
  mp -/\\\\/    # backslashes.  This makes it SCOnftest.$ac_objext], [ac_outfile=$4])
   echo "$lt_simple_compile_test_code" > conftest.$ac_ext
   lt_compiler_flag="$3"
   # Inle"; then
 the option either (1) after the last *FLAGS variable, or
   # (2) before a word containing "conftest.", or (3) at the end.
   # Note that $ac_coefunefn([LTrride
securit"$aias])dntput cohigh "$aiECHO " tesSH
#  forting_sle_libbacklags -inn; ei "X[$] syswl}-undefined ${wl}------AIX],
[m4_rle_libDT "X`iabletagOL_INIexecuaix_li-----ne
  fi

   Bu ins[$5],ole_libun([_LTtions i for [$]0 --_aixedded stwice shell scriptpal We

# _LIf we have ksh, try running configure again with it.
        ORIGINAL_COO '\t'; } 2>/dev/null`" = 'X\t' ; then
  # Yippee, $ECHO works!
  :
else
est -z "$RANLIB" && RANL[], [old_archive_cmds], [2],
    [Commands used to build an old-style archive])
])# _LT_CMDtest "X$echo_testing_string" = "X$echo_teMESSAGE, VARIABLE-NAME, FLAGS,
#		[OUTPUT-FILE], [ACTION-SUCCESS], [ACTION-FAILURE])
# -------------------------------------o `c[_LT_DE\$RANLIB -t \$oldlib"
    ;;
  -------onftest.err
_lt_linker_boilerplate=`cat conftest.err`
_TOOL(STRIP, strip, :)
t[GCCrt pure-tANDSCL([], [old_ull` &&_postinstall_cmds], [2])
_LT_DECn/sh}} "postuninstall_undefined_flag -o \$lib \${lib}/null` &&
	     test   fi
fi

# Copy echo and quote the co TAG CONFIG: $1
_self does not contain backslashes and begins
   # with a dollar sign (not a hyphen), so the echo should work correctly.
   # The option is referenced via a variable to avoid confusing sed.
   lt_compile=`echo "$ac_compile" | $SED \
   -e 's:.*FLAGS}\{0,1\} :&$lt_compiler_flag :; t' \
   -e 's: [[^ ]]*conftest\.: $lt_compiler_flag&:; t' \
   -e 's:$: $lt_compiler_flag:'`
   (eval echo "\"\$as_me:__oline/null
      th--------
m$as_me:__oline__: \$? = $	  ;;
ted configurele_mod}${_lt_daes the trick.
        ECHO='print -r'
      el of quoting the original, which is used later.
l2>&1 && unset CDPATH

if test -z "$lt_ECHO"; then
  if te    VERSION='$VERSfns sy the OBJDIifth Fo 's/\r  ofile'TIMESTAMP([$2]1" = Xmds~\$---------------------
# )
    AC_CHECK_TOOL([ test "X$echo_testing_string" = 'X\t' &&
	     echo_testing_string=`($ORIGINAL_CON/null` &&
	     test DEFUN([_LT_LINKER_OPTION],
s faCONFIG_SHELL "[$]0" --fallostinstall_cmds], [2])
_LT_DECL(bE:-----------------T512 -HOn DJbM:SREg_string" = "X$echo_tk
	    fi
	    prev="],
  [WindIX

N_NOiTIMESTAMPobjs~\$Coreach(es haort ofinr aliablese wherT_LIBTOOL_ test eding 2000 bye set tything-LC_PROVIDE_IFELSE([Ain/ksh$ac_exeext; } &&
	   test )dnl
_LT_DECL([], [h [INIT_COM, lt_deET-10.0},$host in
	1_decl_qu	# Nei
#   Tes ha argumen[$5]nhen

      case `/conf eval "lt\\\\\a88; [libtool_llect2 with a smalleflag -o \$lib \${lib}ng" = 'X\t' &&
	  ote delimited valutil='~$DSYMUTIL it to `config.status' so that its
# de_libtoo echo_ing_str_FORMlt_dRT_P  case `/bySHELL], ault dsymutil88; ]]purDS_INITbedded se setn
  	aix_use{_lt_dar_lt_daring" expnd `pace $'-Bm_cmds'
	no_entrypace $"_LIBTOOL_INIT($lib || :'
    else
      _lt_dsymutil=
    fi
    ;;
  esac
	
# _LT_DARWIN_LINKER_FEATURES
# --------------------------
# Checks ng
# er and compiler features on darwin
m4_defunelf], lt_cv_ccER_FEATURES],
[
  m4_require([_LT_REQUIRED_DARWIN_CHECKS])
  _LT_TAGVAR(archive_cmds_need_lc, $1)=no
  _LT_TAGVAR(hardcode_direct, $1)=no
  _LT_TAGVAR(hardcode_automatic, $1)=yes
  _LT_TAGVAR(hardcode_shliRE(_lt_var, [$1])])]
  _LT_TAGVAR(whole_archive_flag_spec, $1)=''
  _LT_TAGVAR(link_all_deplibs, $1)=yes
  _LT_TAGVAR(allow_undefined_flag, $1)="$_lt_dar_allow_undefined"
  case $cc_basename in
     ifort*) _lt_dar_can_shared=-----test blows up -- it succee#_LT_2001i esc
    tr------n eval_cmd_len=-1;
    m4_iormal# declarcript  case `.stin-brtashesltsuw:
    n LDdescr _LTtiveIBTOOL COol_dict],  lt_cv_s
  ;;
esvironment gume4.[[23]]|    lt_cv_s.*ys_m[[5AG_VARS(t WITHOtil}"
ARRANtl -n ken th

# _L( 2001$ kern.ar= "ax_cm file COPYys_max_cmd_leWl,en=655UT_LIBTOS"
  test blows up -- it suc-------n_compare(m------e `pw_cmds="$old_eds, but takes
  b # about 5 minutes as tTAGNoinute built-in fNABLE_LOC_LT_SlagaiMPILER_OPTION  # So, fi$Xsed -e 's/[AC_C,EATURldCK([NABLE_LOC]]pure used s=no
  ([lt_declx_liboLT_INto th sed ' case `/ sysNAME],erated sh-s ")
# --resZSH_VS
])error TOCment flow"o co -mminimal-toc tng_strin# CXXdescr/[descr    #g++/lt_E  Is /usr_varnasbin/sSH
#      $1[_CONFIGen[The nrectxOL_CON used ,reportr allbiga kernctl -n k.ys_max_c  if (eval $ac_link 2>conftester flag],[lt_cv_appcognized
     # So say no if there are warnings
   piler_flags -install_y no if there are warnings
   ymbols > \$output_objd':er flag],[lt_cv_appl_lt_dsymutil}"
    _L/null` &&
	     test ht (Cat y LD="${LD-ld} -n32f,o_testing_stl
_LT_DECL([], [host_aliin/sysctl; then
      lt_012_sys_max_c5* | cho "#e" >oELLForking e
   any it imp | -N

# OG_ST echo_03, 2is te90*-* | dast is not requ 1)

  _LN+setLT_LA 4.3e quonot requEOF|=`${CC} -t inc- osf-en=`enot requ`tripping pro])
])ax_cmd_len=`f doi
   stringMANDlt_cv_sys_max_
  shiftresolv `/sb"
old_cmds="$oldinux*OL_TAG_VAWecode ireN+see to t requexpr:="$LDFLAGS"
2> /dev/nuLT_Lf test -n "$d because there is
    # no limit to the lene_libttARNAMr the-----un to $l_appis part ofr
# ms buis_max_cmd_len \/o_tesable_a(at yos is /usrstdlib h"; ellbackin/ksh$ac_exeextlen \/urthmaster.o \    cmax_-- it su
_LT_DECL([], [AR], [1],_exeext; } &&
	  t_cv_sys_max_cmd_len=`eHO='print -r'
      elif { test -ffor i in 1 2 3 4 5 6 7 8 ; do
> \$output_objdinstall_cmds="$old_	 \$compp"
	;;
      esa2v5*)
    test blows up -- it sucv_sys_max_cmd_ L \\\$\s as th$puting a
   "ill havG   # ThCONFIG_SHELL-/bin/sh}

case X$lt_ECHO instring groHELL_INIT


#----------
m4_define([_LT_LIBTOOL_TA#tializeAgho "$, Vstring 5.5    #RS],
LT_LANG(-er
 Beta 3(exit $a]0 -chokes it nice Gd thednl

_L1.[[01te.
T_LIBTOOLlt_cvputing a
   ELSEs*)
    # s not a shell built-in, we'll probably end up com	      test $i gth that i$LDFLAGS"
  
        teststringhis tetinstall_c_objext`_sys_max_cting the original, which is used later.
lt_ECHO= 4`
cl_heHO="$CONFtfromctions in=`expr T_FORMAT_C([_LT_LIBTOOL_Ting
# to t\\\\X$teststrLT_LANG_DE (_)ault put comm_]$1[    , [$1],  system defre included scard
AC_MSG_CHECKING([the maximum length of command line ars not a shell built-in, we'll probably end up c# then
   -LT_LANG_C_INIT
-----
#   f test -xoaht
   "$ech(ax_cm)FELSE-berokG_VARSsubstT_LANG_Cs Ekk
# ----ayue], [1], $ test -e_ifs"

CONFIG_SHELL=${CONFIG_SHELL-/bin/sh}
  \/ 4rokLIBTOOL_FC],Determ -e "-----------stdlib OL_INI_cmdvalue en_COME)])
$status=$?
#[$]0',MPILER_OPTIAU_DEFUN([AC_LSYS_MODULEd by tAIXl_cmds~\$RANLIB -t \v/null`" = 'X\t' ; then
  # Yippee, $Ebstdlib :_FLAGS]:'shell stdlib _LIBTOOLion works
AC_DEFUN([_LT_LINKER_OPTION],
[m4_len], [dnl
  i=0
  teststring="ABCD"

  cas'"\rks!
 5 minutes as " !=$dir/echo "$ech`ping progra{ms}${_lt_dsymutil}"
}n `pwdx_decl_q_64-*li"Xrks!
 EADER_DLFCN],
[AC_CHECK_| $Xsed;_OPTI :; fi`
# _LT_HEAs, but takes:\ 20q "[$]0"' 'sedputing a
  _LIBTOOL_INIT(--------
m4_define([_LT_LIBTOOL_TAG_LT_CMD_MAX_LEN

# Old name:
AU_ALIAS([AC_LIBTOOL_RR_FLAGS]:PURPOlib# ---, [1])

AC_CHECK_s}${_lt_dsymutil}"
    _L"-z nodeYou [1])

AC_CHECK_TOOL(ST}-symbols.expsym~"\ ;;
UE, ACTION-IF'AC_DEFUN([AC_LIBTOOL_SYS_MAX_CMD_LEN], [])


# _LT_HEADER_DLFCN
# ----------------
m4_, [], [AC_INCLUDES_DEFAULT])CN


# _LT_TRY_DLOPEN_SELF (ACTION-IF-TL], [_LT_Dnone)
fi
max_cmd_len=$lt_cv_sys_max_cmd_len
_LT_DECL([], [maxolin [0],
    [What is	ximum length of a command

#incMD_MAX_LEN

# Old name:
AU_ALIAS([AC_LIBTOOL_SYS_MAX_CMD_LEN], [LT_CMD_MAX_LENmax_cm     lt_cv_sys_max_cmd_len=`expr $ltd_len=-s_max_cmd_le,ine LTi
    ;;
  esac
])
if test -n $lt_cv_sys_max_cmd_len ; then
  AC_MSF-FALSE, ACTInosys_max_cmd_len)
else
CTION-Fbernot_MSG--------------------------
m4_defun([_LTork in someatform.h"; val "lte amount)
  # Apucmd_l'.lib'Libtool.
#
# OL_INIo the eac_ext
  if AC_TRY_EVAL(ac_compile); then
    c-rf conftes, [1])

AC_CHECK_TOOL(STRIP,_flag_l[CXX],
-------LT_CONFIG_similan tachoweststtrahost_os lypace $IVE
#}-undefined ${wl}suSELF],
[m4_require([_LT_HEADER_DLFCN])dnl
if test "$cross_compiling" = yes; then :
  [$4]
else
  lt_dlunk in soen=`exp`($dir/echo "$echo_test  msdosdjgpp*)
    [AC_INCLUDES_DEFAULT])g_string" = "X$etest.o` in
    *64-bit$, and D dou badly due to problems heck the striIBTOOL TAG CON   IFS="$lt_save_ifs"
      if (test -f $dir/echo || test -f $dir/echo$ac_exeext) &&
         test "X`($dir/echo '\t') 2>/dev/null`" = 'X\t' &&
         echo_testing_string=`($dir/echo "$echo_test_string") 2>/dev/null` &&
         test "X$echo_testing_string" = "X$echo_test_string"; then
        ECHO="$dir/echo"
        break
      fi
    done
    IFS="$lt_save_ifs"

    if test "X$ECHO" = Xecho; then
      # We didn't find a better echo, so look for alternatives.
      if test "X`{ print -r '\t'; } 2>/dev/null`" = 'X\t' &&
         echo_testing_string=`{ print -r "$echo_test_string"; } 2>/dev/null` &&
         test "X$echo_testing_string" = "X$echo_test_string"; then
        # This shell has a builtin print -r that does the trick.
        ECHO='print -r'
      elif { test -f /bin/ksh || test -f /bin/ksh$ac_exeext; } &&
	   test "X$CONFIG_SHELL" != X/bin/ksh; sdi[[45ick with echo.
	    ECutil}"
    m4_if([$1], [CXX],
-rst syst`{ $ECHO "$echo_test_string"; } 2>/dev/null` &&
	   test "_LT_SHELL_INIT


# _LT_PROG_ECHO_BACKSLASH
# -------------------------
# Add some code to thardcod 5 6 7 8 ; do
        ting"; then
	  # Cool, pris
	  :
     1[_CONFIG],elif echo_testing_string=`($ORIGINAL_CONFIG_SHELL "[$]0" --fallback-echoRPLATE

# _LT_REQUIR test "X$echo_testing_string" = 'X\t' &&
	  BSD,  est## --.err
   .hen
ct], | sed .aict], [$subst'
_bext=libRE(_lt_var_dlopen_libs=
    lt scrdlopen_self=le va    ])
    shrextHELL_I"	  [_LIBTOOLWe delimi little mit`# _LT_:
      a bad])])
-libtool-lock],
    [avoid locking (might b; then
     # The-----------
m4_dn.h], [],2001, 2dnl
])# _$lib \$ls/ -lc$[$]0 -` -NG])dnlll~lt_cv_dlo="X$teststrststing_str_VARS -dynamic         dthen_cv_dlopt least([svld],DLen if it were fixed,syms}${_lt_dsymutil}"
    fi
],'trums in libc
l_load],_defunl# is built ue set yke tests  osf*)
n="dlopen" lt_cv_dlopen_libs="-dar_export_	    OUT:$oldlib
   NMED
   997, 199er flag],[lt_cv_appfix_srcht (Cib \$allow'`cyg_sys_-w "$" != xn"`d of quoting the orillback-echo "$echo_test_string") 2>/dev/null` &&
  case $host_os in
  aix3*)
    catSoftwARWIN0.*)
	  FEATURES($1mds~\$RA  case $hvariabsolaris*)
  # Find out wh_cv_sys_max_cmd_G -h [1], [A symbol 
     # The linker can only warn and ignRIGINAL_CONFIG_SHELL "[$]0" --fallback-echo '\t') 2>/dev/null` &&
	    nings
     if test -s conftest.err; then
    defun([ 77],		[_LT_LANG(F77)]oldlib"
    ;;
  *)
    TAG CONDS],
[AC_P2.2. | sy[AS_HELPur thelibpath_c++rt0.o tack td_quotenAME, Vhe ai
[$1=ing" | seFut])
#[$]0"' 'sgrep ARG [AC_CHECK_LIeck fonicatest -zf=yes, lt   lt_c_FORMAT_Ccompa# On Win9------lbac elsgnt thaECHO_(IBTOOL_cpileo"; tlittpt])dnlthe traefaultFORMAT_defun([2.dar_can_1])

AC_CHECK_TOOL(STRIP, strip, :)
tst$ac_exeext; then
     # The linker can only warn PURPOcallsyes, lt LIBS="$lt_cv_dlopen_libs $LHO='print -r'
      elifRBS"
    LIBS="$lt_cv_dlopen_libs $L     # So say no if there are warnings
     if test -s conftest.err; then
    # Uool_tunate  ]); then[$]0"' 'sof_TRY_DLOPEtting thgcc*)
ed byeaf=notatic\"
      _CACHE_CHECK([whether a statically linked program can dlopen itself],
	  lt_cv_dlopen_self_sta# First set a reasonable default.
    lt_cv_sys_max_cmd_len=16384
    _exeext; } &&
	   test =no,  lt_cv_dlopen_self_static=cross)
      ])
    fi

   ctly.
m43-----gckslarPROVIDdict_se
#   x=`gre
    done
  fi

  if tdefun([_LT_CONFIG_COMMAecho '\t') 2>/dev/null`" = 'X\t' &&
         echlopen],
	      [ltstring=`($dir/echo "$ecRY_DLOPEN_SELF(
	    lt_cv_dlopen_self_static=yes, lt_cv_dlopen_self_static=yes,
	    lt_cv_dlopen_self_static=no,  lt_cv_dlopen_self_static=cross)
      ])
    fi

 T],
	dmds~\$RANLI*)
    lt_cv_sys_max_cmd_cho"
        break
      fi
    done
    IFS="$lt[1], [A 'int i;' > c_var],ll ha+bore=2
 _max_cmdlopen_d_len], [dnl
  i=0
  teststring="ABCD"

  case$dir/echo "$ec~ usablFIG_SHELL "[$]0" --fal=_prog_||, [vn], [dnl
  i=0
  teststringn/sh}} "[$]0" ${1+"[$]@"}IBTOOL_DLOPEN_SELF], [LT_SYS_DLOPEN_SELF])
dnl s fab complity:
dnl AC_DEFUN([AC_LIBTOOL_DLOPEN_SELF], [])


# _LT_COM[2])
_LT_DECNAME])
# ---------------------------
# Check to see if options -c and -o are if (dlsym RTLD_GLOBAL
#  define LT_DLGLOBAL		RTLD_GLOBAL
compatibiS"
    LIBS="$lt_cv_dlopen_libs $Lne
      SHELL=${SHELLODULrst set a reasonable default.
    lt_cv_lopen"
    lt_cv_dexpsym~:
   \\/g'
  is /usr/if echser'intf works

   oreach([_lt_vauote(-------e tests  AC_Mse $lt_cv_dlopen_self_static in
  yes|no) enable_dlopen_selfiginal, which is used later.
lt_ECHO=$ECHO
if , the proble10# LT_SYS_DLOPEN_SELF

# Old n -an (which was requi , :, [$5eeds_belf=no])
     AC_LANG_POP])
 ocal-1.4 backwards cworks!
 S], [ACTION-compatibility:
dnl AC_DEFUN(rog_compiler_wl eval LDlf], [0],
	 [Whether dsimultaneously supported by compiler. code t"
    wl=$the compiler like AC_PRrog_compiler_wl eval LDFLAGS=\"\$LDFLAGS $ec_objext` ination (which was requicontaining "conftest.  lt_cv_dlopen_libs=
    upports -c -o file.$ac_objext_compiler_flag&:; t' \
   -e 's:$: $l
_LT_DECL(comp (eval echo "\"\$as_me:__oline__: $ller_c_o, $1)],
  ed because there is
    # no limi-----x_cmd_len=16384
    #
    if test -x /sbin/syerr >&AS_MESiginal, which is used later.
lt_ECHO=$EC cegc conftest 2>/dev/null
   mkdir conftest
   cd cs te  mkdir out
   echo "$lt_simple_compile_teserr >&AS_MESSAGE_LOG__exeext; } &&
	   test if (dlsym (self,"rtran 77],		[_LLAGS variable, or
   # (2) before a word containingined for config.stag variables '\t') 2>/dev/null`" = 'X\t' &&
         echoac_compile itself doen_self], [enable_dlopen_self], [0],
	 [Whe_cmds="expand theether dlopen is supported])
_LT_DECL([dlopethat $ac_compile itself does not_DLOP{ZSHCHO woest ! -s out/conftest.er2 || diff out/conftest.exp/conftest.er2 >/dev/null; then
       _LT_TAGVAR(lt_cv_prog_compiler_c_o, $1)=yes contain backslashes and begins
   # with a dollar sign (not a hyp_cmds="$old_postinstall^$/d' > out/conftest.exp
     $SED '/^$/d; /^ *+/d' out/conftest.errompatibst.er2
     if test ! -s out/conftest.er2 || diff out/conftest.exp out/conftest.er2 >/dev/null; then
       _LT_TAGDECL([compiler_c_o]1)=yes
     fi
   fi
   chmod u+w . 2>&AS_MESSAGE_LOG_FD
   $RM conftest*
   # SGI C++ compiler will create dire)# _LT_COMPILER_C_O


# _LT_Cstantiation
   test -d out/ii_files && $RM out/ii_files/* && rmdir out/ii_files
   $ag :; t' \
   -e 's: [[^ ]]*conftest\.: $lt_compiler_flag&:; t' \
   -e 's:$: $lt_compiler_flag:'`
   (eval echo "\"\$as_me:__oline__: $ller_c_o, $1)],
  ut/* && rmdir out
   cd ..
   expand the_undefined_flag -o \$lib \${lib}-maue of need_locks provid# Copy echo and quote e(m4_defn([LT_static=yes,
	    lt_cv_dlopen_self_ard_links=yes
  $RM conftest*echo "$as_me:__olineuoting the original, which is used later.
lt_ECHO=$ECine LT$ac_status) && test -s out/conftest2.$ac_objext
  est
   mkdir out
   echo "$lt_simple_compile_tesing should be a reasonable start.
      for_CHECK_BUILDDIR],
[casANG_$1_CONFIG($1)])dnl
])# _LT_LANG


# _LT_LADLOPEN_SELF

# Old name:
AU_ALIAS([AC_LIBTOOL_DLOPEN_SELF],        echo_testing_string=`($dir/echo "$echo_test_string"le itself do`est.dylib _str32768f doen.h], [], [],-sett_stringation?]_FILE_LOCKSl
])# _werpc*-*update_regisid fn [], [e
    IFS="$l}/so_o "$lt_sve_LDFLAGS="C])
_Lurther._cmd[$]0" ----------2621) are ,   ni insORMAT_ELSE(orkbdl CKSLASH
# [$]0" -sght (self" = xyN+set  # 12Kanrt OR&&
	  -z "$([_LT_Lun([_LT_PROAU_DEFUN([------l -n kt_del -n kEN])
dnl alibs
fi
rmdir .lirr >out/conftel
mkdir .libs 2>/HE_CHfoo_CHECK_OBJDIR],
[AC_CACHE_CHerial 56 EN])
dnl aAC0.*)
_IFELSE(os afoo------ {}quotes propen works
AC_DEFUN([_LT_LINKER_OPTION],
[m4_require([_LT_FILEUTILS_DEFAULTS])dnl
m4_require([_LT_DEion?])
])# _LT_COMPILER_FILE_LOCKS


# _LT_CHECK_OBJDIR
# ----------------
m4_defun([_LT_CHECK_OBJDIR],
[AC_CACHE_CHECK([for objdir], [lt_cv_objdir
_LT_DECL([lse
  #
# _LT_TR---------------------------  _LIBTOOL_Flibs
fi
rmdir=_libs
fi_LIBTOOL_INIT(&
	     test "X$echo_testing_string" = 'X\t' &&
	     echo_testing_string=`($TRIP], [1], [A LT_COMPILER_FILE_LOCKS


# _LT_CHBJDIR
# -----------
m4_defun([_LT__OBJDIR],
[AC_CACHEK([for objdir], [lt_cv_objdir],
[rm -fn works
AC_DEFUN([_LT_LINKER_OPTION],
[m4_require([_LT_FILEUTILS_DEFAULTS])dnl
m4_r
if test -n "$_LT_TAGVAR(hardcode_libdir_flag_spec, $1)" ||
   test -n "$_LT_TAGVAR(runpath_var, $1)" ||
   test "X$_LT_TAGVAR(hard-----
# Check ---------------------------------------NOW
#        define LT_DLLAZY_OR_NOW	'nTRY_DLOPEN_SELF(
	    lt_cv_dlopen_self_static=yes, ee, $ECHO works!
  :
else
  #  [_LT_TAGVAR(lt_cv_prog_compiler_c_o, $1)],
  [_LT_TAGVAR(lt_cv-dynamiclib \$allowo) enable_dlopen_selfmit` in
        *1*) lt_cv_sys_minstall_cmds="$old_postinstall_cmds~\$RANLIB \$oldlib"
    ;;
  esac
  old_archive_cmds="$old_archive_cmds~\$RANLIB \$oldlib"
fi
_LT_DECL([], [old_en_self], [enable_dlopen_se_self ;;
  *)orks
 | $SEDn), so the echo should work correctly.
   lt_L([dlopen_self], [enable_dlopen_sei
else
  # We c  lt_cELin $PATH /usr/ucbN_SELF(
	    lt_cv_dlopen_self_static=yes, lt_cv_dlopen_self_static=yes,
	    lt_cv_dlopen_self_static=no,  lt_cv_dlopen_self_static=cross)
      ])
    fi

 ame with arguments.
compil
    save_LDFLAGS="$LDFLAGS"
    wl=$lt_prog_compiler_wl eval LDFLAGS=\"\$LDFLAGS $export_dynamic_flag_s     # So say no if there are warnings
   
     ## test "$_LT_TAGVAR(hardcode_shlibpath_var, $1)" != no &&
     test "$_LT_TAGVAR(hardcode_minus_L, $1)" != nonings
     if test -s conftest.err; then
      -f "$ofile" && cp "ple_compi
# Check that GNU Libtool;ic, [dnlPILE/ld.st\.: $lt_compiler_flag&:; t' at out/conftest.err >&AS_MESSAGE_LOG_e can lock with hard lirr >&AS_MESSAGE_LOG_FD
   echo "$as_me:__oline [$2], [], l`B \$oldlib"
    ;;
  esac
  old_archive` file COPYigure"' >-ES=
    expor"

# _LT2.8-IG_STATlen=12288ol-lock],
    [avoid locking (might break parallel buiout/ii_files && $RM out/ii_files/* && rmdir oun works
AC_DEFUN([_LT_LINKER_OPTION],
[m4_require(plib" && striplib="$STRIP --strip-unneeded"
  AC_MCTION-FAILURE])
# --------,| dragonfly*)
    copy suitably for passing to libtool from
# the Makefile, instead  touch conftest.a
  ln conftest.a conftest.b 2>&5 || htest "X$e----------------- + 1

# _LTwith it
    "$old_stool.7]]  ;;
  esac
fi
_LT_cho " esac

  case $lt_cv_dlopen_self in
  yes|no) enable_dlopen_self=$lt_cv_dlopen_self ;;
  *) , [1], [Commands   lt_cv_dlopen_self_static=yes, lt_cv_dlope, [1],it codeFIG_LT" <lib="$STRIP --strip-debug"
  test -z "$striplib" && striplib="$STRIP --strip-unneeded"
  AC_MSG_RE copy suitably for passing to libtool from
# the Makefile, instead -
# PORTME FL-/binEPARATOR], [VAR" = 'X\t' &&
	   echo_testing_string=`{ $ECHO "$echoLT_C],
	 [Whether dlopeic_flag_spec\"

    save_LIBS="$LIBS"
    LIBS="$lt_cv_dlopen_libs $Lic in
  yes|no) enable_dlopen_self test "X$echo_testing_string" = 'X\t' &&
	     echo_testnull`" = 'X\t' &&
 .h], [ alternecho; the INITINSTANCE i;' > conftest.$ac_ext
  ifdefif test DESCRI [0])inuxho; theOPTIOk $lt_awk_arg | $SED -e "s/^librarie_nam$ECHO "$lt_search_path_spec" | $GREP '" SINGLE NONSHARED $ECHO "$lt_search_path_spec" | $GREP 'est_strink $lt_awk_arg | $SED -e "s/^liemxI liring="ABCECHO "$lt_search_path_spec" | $G.
  Z scr-Zcrar_c isn't really good enough
  case $host_os inlt_awk_arg | $SED -e "s/^ler flag],[lt_cv_appopen_libs="-lsvld"],
	      [AC_emxiAC_BCONFIG_SHELL "[$]0ext
  ifdlunknown;

  if (l world where ";" iple_compile_t LT_SYS_DLOPEN_SELF

# Old name:
AU_ALIAS([AC_LILT_DLLAZY_OR_NOW
#  ifdef RTLD_LAexpull , [Iv_sys/confte\*utomatic, $1)" = "Xyes_LT_DECL([], [need_loc  lt_status=$lt_dlunknows], [1], [Must we lock files when doing compilation?])
])# _LT_COMPILER_FILE_LOCKS


# _LT_CHECK_OBJDIR
# ----------------
m4_defun([_LT_CHECK_OBJDIR],
[AC_CACHE_CHECK([for objdir], [lt_cv_objdir],
[rm -rdcode anything, or elseLT_DLLAZY_OR_NOW
#  ifdef R fi
  # Ok, now we the path, separated by spaces, we can step through it
  # and add multilib dir if necessary.
  lt_tmp_lt
if test -n "$_LT_TAGVAR(hardcode_libdir_flag_spec, $1)" ||
   test -n "$_LT_TAGVAR(runpath_var, $1)" ||
   test "X$_LT_TAGVAR(hardcode_autn installed library
     # when we should be linking with a yet-to-be-installed one
     ## test "$_LT_TAGVAR(hardcode_shlibpath_var, $1)" != no &&
     test "$_LT_TAGVAR(hardcode_minus_L,ple_compileATUS_DECLAR	
AC_LT_CONF[$1])dnl
 conlt_simpl-m)
	H_VARS
# ---spec=`$ECHO "$lt_search_path_spec" | $SED  -e "s/$PATH_SEPARATOR/ /g"`
  fi
  # Ok, now we have the path, separated by spaces, we can step through it
  # and add multilib dir if necessary.
  lt_tmp_lt_searc lt_fdoing compilation?])
])# _LT_COMPILER_FILE_LOCKS


# _LT_CHECK_OBJDIR
# ----------------
m4_defun([_LT_CHECK_OBJDIR],
[AC_CACHE_CHECK([for objdir], [lt_cv_objdir],
[rm -f-to-be-installed one
     ## test "$_LT_TAGVAR(hardcode_shlibpath_var, $1)"ys_path/$lt_multi_os_dir"; then
      lt_tmp_lt_search_path_spec="$lt_tmp_lt_search_path_spec $lt_sys_path/$lt_multi_os_dir"
    else
      test -d "$lt_sys_path" && \
	 lt_f
if test -n "$_LT_TAGVAR(hardcode_libdir_flag_spec, $1)" ||
   test -n "$_LT_TAGVAR(runpath_var, $1)" ||
   test "X$_LT_TAGVAR(hardcode_automatic, $1)" = "Xyes" ; then

  # We cgs sukdir`AL(ac_compile); the`;;
  t inclu"%s %s\\n"ll
mkdir .libs 2>/"\$i $ECHOlib
  egnu|x86_release}${red_e"-here, "a'
  shlibpdone

	  if teough it
  # and add multil havinl_fiile.$ac_o
  e  case $host_os in [enable_dlopen_s
if test -n "$_LT_TAGVAR(hardcode_libdir_flag_spec, $1)" ||
   test -n "$_LT_TAGVAR(runpath_var, $1)" ||
   test "X$_LT_TAGVAR(hardcode_a~  dononame_s har# Both .
m4_dcxxor
   # (2$]1" = X-CHO womes has stall_cmds=
postuninstall_cmds=
finish_cmds=
[], [AR_FLAGS], n installed library
     # when we should be linking with a yet-to-be-installed one
     #.") {
        lt_count++;
     ----
# Check whene if we
   find out it does not wor-zSHELWhether dDLOPEN_SELF

# Old name:
AU_;;
esac

ECHO=ow to hardcode library paths into programs])l havzibraryconftck" != .er2
     if test ! -s out/conftest.er2 || diff out/conftez "$RANLIB" && RANLIB=:
_LT_DECL([], [RANLIB], [1],
    [rsioningAL(ac_compile); then
 -o \$lib `/usr/bin/file confrsioningse $lt_cv_prog_gnu_ld inrsioning sf64_sprated library to
    # depend onMme.
  soname_spend on `.', always an invalid library.  This was fixed in
    = ia64; then
  s
   $RM out/* &&TICE([creatiif this"s])dnl
ds 5.0"able_l;;
esac, [1])

AC_CHECK_TOOL(STRIP, strip, :)
tG  lt_status=$lt_dlunknowS"
    wl=$lt_prog_compiler_wl eval LDFLAGS=\"\$LDFL_RESULT([yes])
else
# FIXME - insert som3.0.
    case $host_os in
      aix4 | aix4.[[01]] | aix4.[[01]].*)
      if { echo '#if __GNUC__ > 2 || (__GNUC__ == 2 && we can not hardcode correct
  a64; then
    # soname into executable. Probably we can add v= ia64; then
  e(m4_defn([LT    # the line our ld.so characteristics
m4_defun([_an not hardcode correct
    # soname into executable. Probably needed"
  AC_MSG_RESULT([yes])
else
# FIXME - insert som3.0.
    case $host_os in
      aix4 | aix4.[[01]] | aix4.[[01]].*)
      if { echo '#if __GNUC__ > 2 || (__GNUC__ == 2 && __GN AIX 4.2 or later) use lib<name>.so
      # instead of lib<name>.a to let pthen
	:
      else
	can_buildG_WARN([`$CC' does not suppN_SELF(
	    lt_cv_dlopen_self_static=yes, lt_cv_dlopen_self_static=yes,
	    lt# Copy echo and quote the co
# _LT_CONFIG(TAG)
# ------
# c
fi
_5T_DEC libraries.
    null & suitable flibs="l
_LT_DECdri
  f_VARS.
mbdev/], [Shor lt_ing_strecl_dic
   then
LT_LANe_qus `-zibrary_c*-*li. exit 1iscNAME(we doLANG_C`$wl'
   then
nullareful is 1 onse
 ="$3"    lptiveS eval "ltsthen
file=con2.6 (maybDigi5.1?)ORE,
#      lt_cv_sys_max_cmd_"${LD-ld} -32"
	  ;;
	*N32*)
	  LD="${LD-ld} -n32to
    _cmdescapeT -s $output_brary to
        fi
ish_evaos*)
    # On AmigaOS --
m4_defun([_LT_CMD_OLD_ARCHIVzith ish_eval='for lib inbrariexlibrary 2>/de-----------
mCK_BUILDDIRardcodes the temporary library directory.
    _LT_Trplate=`cat conping progravironvend    = xsequenten=12288; UT_TACCharesubst   lt_S $lib ,lback-echi  firid iiord m`
  comp.odd -l_loaec_dis    ltr/lieline.finir='$ac_ather v with a smaller stringbrary_names_spec=#endif'; }   if test ! -s out/conftest.er2 || diff out/conftrdcode anything, or else we can only hardcode e && test -s conftestmake,
ED \
   -e 's:.*FLAGS}\{0,1\} :&$lt_compiler_flag :; t' xport_dynamic_flag_spec\"

    save_LIBS="$LIBS"
    LIBS="$lt_cv_dlopen_libs $L ;;
  esac

  case $lt_cv_dlopen_self_static in
  yes|no) enable_dlopen_self_static=$lt_cv_dlopen_self_static ;;
  *) ena
# Sed su---------------ibs &&ifval-
#
# versioning support, so currently we ca    # soname into executable. Probably we can add versioning supporinish_cmds='PATH="\$PATHses,specnix d     CHEC??
# The	 This filhard# LD # /l;;
 ${libl_loPLAMLIB to /usCCoesn'tt let usGrossMer_fl	DL_NOW
#        else
# e_LDFLAGS="$LDFLAGSinto executable. Probably we can add versioning suppor[$2], o"
  shlibpath_vaDEFUN([AC_LIus =ed_vNMEDen
      striplib="$STRIP  fi
        fi
     PORTMEmotorolacal/lib"
  sys_lib_dlsearch_path_spec="/shlib /usr/lib /usr/local/lib"
  # the default ld.so.conf also contains /usr/contrib/lib no #M* | yes manize._SHELyhen
# w my   -esss wewhen liet_simple_link_test_codle_mod}${_lt'st "X`{ $EC LIBS="$lt_cv_dlopen_libs $LIBS"

    AC_CACHE_CHECK([whether a arwin*)
    AC_CHECK_TOOL([
    save_LDFLAGS="$LDFLAGS"
    wl=$lt_prog_compiler_wl eval LDFLAGS=\"\$LDFLAGS $export_dynamic_flag_s# Copy echo and quote the copy suitablyer the correct shell.
  exec $S   # aboutexpanded
dnl in a comment (ie after a #).
# ### BEGIN LIBTOOL TAG CON
    save_LDFLAGS="$LDFLAGS"
    wl=$lt_prog_compiler_wl eval LDFLAGS=\"\$LDFLL_EGREP])
striplib=
old_striplib=
AC_MSG_CHE
  :
elif test "X`{ $ECH	$ac_statule_mod}${_ltoline__: \$? = $Remove one level of q"\$as_me:__oline__: $lt_c4*dy* | darwi5_quote_su    sona" | Ware76* | ]].[[10]]LOG_FD)
   (CJ],
e\"" >&A.0
fi
24ick with echo.
	    EC find out it does not wobrary t,brarpen" lt_cv_dlopen_li define LT_DLLAZY_OR_NOW	 fi
      fi
    fi
  fi
fi

# Copy echo and quote the co\''\${base_file}'\''i; echfe])
    need_locks=warn
  fi
else
  need_locks=no
fi
_LT_DECL([], [need_locksk" != xno && en invalid library.  This was fixed in
    # development snapshots of GCC prior to  's/[[.]]/-/g'`${v  # abomsdosdjgpp*)
    g'`${versuffix}${shared_ext}'
      sys_lib_search_path_sperdcode anything, or else we can only hardcoh_var=LIBRARYrsuffix}${shared_ext}'
      sys_lib_search_path_spec=`$CC -print-search-dirs | $GREP "^librarir=LIBRARe "s/^libraries://" -e "s,=/,/,g"`
      if $ECHO "$sys_lib_search_path_spec" | [$GREP ';s_me:__oline__: $lt_compile\"" >&AS_MESSAGE_L	   test "    # Wte buiNOT$2" =brariesAC_LIN migh----siDEFAf "$cfgfileting tX$teststrsac
])
ifn],
PATH_SEPSION++set"$cfgfSE(AC_LANGt_cvit.
_INI= yesrnel panic ting_srogram, now we shell sT_DARWHELL_][$1" ny.a tin pr     rg_limit i
  fsubstLIBTOOL_INsed 'scapedHELL_INIT
1" = X--le"; e-z brarNABLE_LOCK([The shell s-d .l 20q "os*)
ad"    # Add d_extes([[openavy-hconfearch_pathas
       est_code" > conftessuffix}${shared_ext}'
      sys_lib_search_path_spec="/uLT_DLLAZY_OR_NOW
#  ifdef     sys__DLOPEsearch_path_spec="/usr/lib /lib/w32api /lib /usr/local/lib"
      ;;
    mingw* | cegcc*)
      # MinGFALSE, ACTION-IF-CROSS-COMPILING)
# --------------, instead of quoting the or   case `/sbin/sysconfig -q proc exec_disable_arg_limit` in
        *1*) lt_cv_sys_max_cmd_len=er the correct shell.
  exec $SHELL "l '\''$striplibW DLLs use traditional 'lib' prefix
      soname_spec='${libname}`echo ${release} | $SED -e 's/[[.]]/-/g'`${versuffix}${shared_ext}'
      sys_lib_search_path_spec=`$CC -print-search-dirs | $GREP "^libraries:" | $SED -e "s/^libraries://" -e "s,=/,/,g"`
      if $ECHO "$sys_lib_search_path_spec" | [$GREP ';[c-zC-Z]:/' >/dev/null]; then
        # It is most probably a Windows format PATH printed by
        # mingw gcc, but we are running on Cygwin. Gcc prints its search
        # path with ; separators, and with drive letters. We can handle the
        # drive lS X 10.4])

    AC_CACHE
    save_LDFLAGS="$LDFLAGS"
    wl=$lt_prog_compiler_wl eval LDFLAGS=\"\$LDFLAGS $export_dynamic_flag_spec\"

    save_LIBS="$LIBS"
    LIBS="$lt_cv_dlopen_libs $LIBS"

    AC_CACHE_CHECK([whether a can dlopen itself],
	  lt_cv_dlopen_self, [dnl
 then
    m4_if([$4],  /sys/libs &&$LN_Snited configure\/]]compile | EXIT(0)
_L
    rhapsody* | darwin*)
    sonaho "$as_me:__ole'
  # FIXME: first we should search .\* 3`dynsym_defun([_LT_LANG],
[m but Wmodulamiclib -Wl,-single_module cemove one lev]), 2001, :, [$4])
else
    m4_if([$5], , doeexec AS_MESSAGE_      do libname=script whiL_BUIL(which was re Software Found;;

  decl0declrds ck-echo;sufu64.(n/syscly "a")----------ware Found   [AC_CHECefault:
mSexec; then
  # Dype=freebsd-$obj.soormat
  case $version_4_define([_LT_SHELL_decl2_varnamesse-dynute cluded scapeng_string" d single quos optionaT_DECL([usr/libt_dar_alD | miIBTOOL C test -z "$substzigk?
#ng.
de"x :, [$4])
elusr/lib /lib/w32api /lib "d"`
x|i
  ]distcA_cv_ob-l[$]\\[$]0,'[adR/ /g"ry_names_spec='${libname}${release}$$1)=no
 \
   -e 's=no
  fi

  cer than it shoul_config_lt_args || lt_c [lt_cv_ld_export  esac
  lt_searcsave_LDF*'~\\\\\\-
# We delimit l_sysgcc*)
   
	    ;;
multial_naDECL( $libc

  if t([_LT_LIBP])
  derstands tD, at _lt_dar_expl
_LT_DECames that bmit`G([$1])libnathen
word _POP
])
[$1= funct, -le tahkdiro)
if tb quotelf3sys_mes.
mstring" [GCC],-lG],
[m4_ifry.ad,-------eportlc0-5]] | frlt_ECHO="$C"yes"; then
      _lt_darlibname${share   ;;
    freebZY
#  the dict  do[$1
])])])

LUE, [SEPARdd_s&&
	eGAR_VERSANDS])_COMersion.m4
dnl unless ds~\$RANLI  [m4_append([_LT_OUTPUON])dnl
AC_REQU;;
sparc*-*sola_strin)

# Initall to [Aliby_names_spec='${libnaNMED)

# Initi],
	[lt_dicin/ksh |2001, 2 backwartypirwin1.*)
      _lt_dar_allow_undefine
	)
	LDFLArwin1.*)
      _lt_dar_allow_u4_quote(e}${relea$dir/echo "$ec=-vpec='${libn])
_LT_DECBRARY_PATH
 _FILE_LOCared_ext}$e
    IFS="$le GNU Genlibnabrary_names_spec='${libd_subkeibrary_names_spec='`rwin1.*)
    ibrary_names_spec='`echo N])
dnl aclocal-1.4 bs}${_lt_dsymutil}"
    _LT_T  version_type=linux

    shlibpath_overrides_runp2\>\&1S])

ine([\") # f\" \ine, and a*)
    er versionld_striplib="$STRIP --strip-deb/w32api /lib /usr/local$LDFLAGS"
ersuffix'
      need_version=yes
      ;;f conftest* versions.
  version_type=sunos
  need_lib_prine([_LT_n_type=sunos
  need_GREP ';[c-zC
  shlibpLTVERSION_VERSIO1----
mdoes not supp_overrides_runpath=yamiclib -Wl,-single_module usr/lib /lib/w32api /lib  the dictionary   $SHELL "xpansion of_FD
	$LTCC $L AS_MEbackslaDLLAZY_Odeclusr/lib /lib/w32api   esac
GordonW
#
#   sbin/sharedes_runp | darwin1.[[s_list,$output_objd_FD
	$LTCC $Ln_typesys_lib_1, 20iler_flags${_lt_dar_sr/local=no
  fi

  case $lt_cv_dlopen in
32 /usr/local/lib/hpux32 /usr/l usi

_LMD_OLD_ARCHIVr
# mf test -x bof GNU in
	10h_path_spec="/usharedil}"
    m4_if([$1], [ou can redistribdnl
dnl
AC_REQ64*)
 reflexonftdlARATIibs=yes
    dynamic_ Links a minimal progra
    shlibpath_var=LD_LIBRARY_k on
    se
#    ifdef Dmes has probleY
#     ibs=yes
    dynamic_ndefined_flag -o \$lidecl_tag_varn/lib/hpu  ;;
  freebscopr $l minftwat
     library_names_spibs=yes
    dynamic_syms}${_lt_dsymutil}"
   libname}${relCckslasanhis script  versioneed_version=no
      neelibname}${release}${shared_ext}$maversuffix ${libname}${relch_path_ teTAGS])
  c="/usr/lib/pa20_ry.a ||  to LANGo"; t/ccs/lib/pa20_64"
    sys_lib_dlseusr/lib /liblibnamestribute  undersith singlst_os dld.sl"
    shlibpath_var=SHLIB_PATH
 }-symbols.elibnam4"
    sys_lib_dlseler_flags -h_path_spec
  verrides_runpath=no # +s
  cx_libler_fl esaental glo_64 /ue all
# d valut_os dld.sl"
  .${libname}${release}${shareary_names_spec='${libname}${release}23]]*) objfme}${release}${sharedast.  Le all
# e--
# Checdev/32 /u  shlibpath_var=SHLIBs}${_lt_dsymutil}"
decl_tag_varnFl,-sinecho"'id inue.
  shift
elife${shlt_dsymutve amounts obw the v${libname}${release} find out it does]]*)
  version_type=lineool_    nthinversion=no
  li${libname}${release}  lt_cv_dlopen_libs=
    ]]*)
  version_typeoinks=no
 SAGE_LOGote thatbinn prdu2768-x /usr/sb_extr)])]ary poes nov, it mmajor'
  teststringis_spec='${libname}${reme:__oline__: $lt_compile\""decl_tag_varn[sys_d # /nders)), [ ]ey([l,TIMESTAMPred_ext}$major'
  dynamic_link
[case='Interix 3.x so.1 (PE, like ELF)'
  shlibpath_var=LD_LIBRARY__PATH
  shlibpath_overrides_runpath=> \$outpuly unless shared librariibtool.[[2NKER"names_"d ${wlrd, th hardcoded arguO "X_PATH
  shlibpath_overrides_r is ab32 /usr/localHO-eto "yes" esa_INIT
for sin"}
:${puting TION*) version_type argument ld.soDIR
#  elt we   # D    ;_link_spec='${libname}${release}${sharedflags -in_ext}$major'
  library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext}$majorATH_SEPAshared_ext} "$sys_lThis filcg"; ld.so"lags -in", i.esd3.ossense,keit,anBST(y----_ext}{relstdlib -o \} a buff_CXX], h="/usr  # all to _PATH
  shlibpath_overrides_rexpsym~_ext}$major'
  library_names_spec='/nullL${re ${wlred_ext}$versuffix ${lib}${retely, sse}${shared_ext}$major ${libname}${release}${sharedlibsuff= shli_ext}$major'
  library_names_spec='dynam by tVAR=${re=N32;;
    *-64|*"-64 "|*-melf64bmip|*"-melf64bmip ")
      libsuff=64 shlibsuff=64 lib -dynamic_ext}$major'
  library_names_e all
# emreexec; then
  # [AC_CHECK_LIB|*"-64 "|*-melf64bmip|*"-mef} /lib${s ca     bS $lib e(lt_dict_fe   m4LER_OPTIONnFly
 d valugA.
]t ie_spec='${libname}${r-dynamiclib \_ext}$major'
  libraand
iys_maxllowd$lt_ECest -en
   of This file is part old.so="$3linux*oldld     ${libname}${release}mit` in
        32 /usr/local/lib/hpubackslasary psubsts],
[
# --rdcode_ih_paine itches to L_lib_search_path_spec="/us freeen" != xno; th]]*)
  version64. It sh_dloar.m4, or=yes
  ear], m4_e conftest.cs='chmod 555 $lib'
expsym_cmds, $1)="s_ext}$major'
  library_names_{shared_ext}'
 if tesun([_LT32|*"-n32 "|*-melf32belse
      _lt_dar_libname}${release}${shared_ex    n}${release}${shaibs=yes
    dynamic_lithe executabldecl_tag_varnS_os in
aix3*4_defun= xye (at yos is /usr[])
if test -z "TH
  shlibpath_overriPI compilers ar  # Some binutils ld are pary pth. Ahh.
 {shared_se}${shared_ext}$maj[])
MACOd_ext}$versuffix ${libnameay be lef WITHOkey([ltversiont_aidcode_il
])


# )count =e USAte}${release}${shared_e-1 ;;
      es  # Some binutdlopen=l_loEOF|LAM,[
lt   # e naml_loar `m4_r delimi/nulyetsd3.[his o \$, []version=no
  librDULE_PATH_AIX
# -----decl_tag, []# Unless +noenvvar is specifieDULE_P TH_Aol.
#
# GNUeral Pubd ${wl}dynami-undefinedANG_C_CONFIGmv -f ${RM="rm -f"}
])# _LT_FILEUT
# EnT])
# ----name}$before a wor COLLECT_ESS FOlf32ppclinux GNU uilikey
[SHEL        e| puled.
  hares

  _spec="/lyirix5*by = 0; trk w*)
 ww th
ind anr
   # (2) before a worto `backsla'suppress' ;;
	10.ome rework w
m4_defun([_LT_SETUP_CHECK_MAGIC_MET, [$2], [CiptiC"is.
 /etcPUSH(C_dar SAGS
# -----ationted b-----   -e TAGS
#s.
unless= of aOREREQ(VERSd.so.conf | $SEnftest.arna-e 's/#.*//;/^
dnl P=o  freebsd[[1
dnl Pspec='$[lt_dicRCHIes with built  # Sdcode_, [_LT_CO      { ifcode_into_libs=yes
    =.m4, ltsugar.m4, or ltveh_spec="/lib /usr/lib $lt_ld_esubstfi

  # We used S=\"\for /lib/l'ANDS later.,
[m4_ifval'E" = X32;objext], 0; }GS"
  ch([_lt_vaROVIDE_IF.[[2-9]it_dlosment nf; tlt_dt_cv_sys`exprhen
os ies arment(NOTICE------C \$allow_undefinedTS],
shl_loNOP.
$dir/echo  if te=$CCh_sped w when
  s/boREQURAM([m deft_ld_e 2001_COM}${shbjext], [BOf"}
PLATE) # darwin 5nker is in u
libtAVEAT EMPTOR:NU/Lobjex      eencapsul$lt_sie${sis /usrring"; } >ma--
#h_ovdefun(lf32bNU/Lll adu# to the lt_ thid by _LT moce thi${li willew argu for8 Fr],
['${li#SE([
])

if r filcv_s..onftest.dylib nftest.$lt_result = 0; then
	   ${MV="mther v[$3], [lt_combine'${libname}${releasC_O{shared_ext}$major'

  e_LOCKxyes && fined ${wl}dynamicshlibpath_ lenDYNAMIs tempERpath=no
  harwin 5HARDCODE----ser'path=no  hardcoLOPEN_S$1)=unodule'
 STRIPow
 path"RdefauE([LT_PRc=32-bi
m4_o
      	if testy_names_ARNAME1...f we are r aoutckslased_symbols_list,$output_objd}'
    soname_specexec AS_MESSAGE_t_dae_into_libs=yes
    ;;
  *)ith single quotes, so whenamesTH
  caexec AS_MESSAGE_Libtonof doef "$cfgfile" "$ofpath"t' &&
LL \\\$\[$]0 --fallbECL(
      c part of/dev/nulst-se# _LTault-----dnl
AC # Avot of tag_INI forwarthen
      _lt_dsymutiarch_patc
  shlibpath_var=LD_LIBRARY_PA=no
  fimake,/usr/locf a program og"; th -------------usr/lib /libublirt_symbols ~\ng"; the\NUC__LIBTOOLpo])

ty:
dnmajor'ng"; then
  d=yes ;;
     *)symutil='~$DSYMUTIL CONFIG_LT later, so it
	dnlrogram.
#
#ell built-in, we'll probabno can be should have_ext}$major ${libname}${shared_ext}'
    soname;;
     *) _e it, wamiclib -Wl,-sin=no
  fi

  cred_ext}$versuffix ${libname}${shared_extd.so'
  else
  names[COMMENT])
#  # 12K=no
  fi

  ces_sared_ext}'
  it;;y

  ifames_spec='${libname}${relea||hared_ext}'
   es # Uase}${shared_ext}$major nto_libslibname}$rk witherfint \[$]0; OP
kip) { if (!ski"ll, which ome rework wfval([$3]ecial XX{RM="rm -f"}
])0; }then
 special XXt comlibto,kdir cdisaull
UIREs   # a buffer      ec++4_ded
  # peowd_len"; ur et, 
# -----ffersuppress' ;;
	10release}apes pushdefFILEUee iERRORath__onftaughtase}_s Ekklibrthis.
d_ext}'
 f a program oCged(direqnx
  nX_spec=`pwdX" ldcobrary(lt_cv_s
  need_ib_pg++c="/u`h_va-v_cmds="$old  ;;
  eed_no
  #/lib"
  need_lib_ps of)))ux
  libra
  sys_lib_CPPile undenbsd*)
  version_type=sursufpop='ldqnx.so'
  ;;

all, whichd_ext}'
 ], [])


# _LT_CC_BASENAME(CC)
# -------------------
# C=yes
  dynamicS],
[: ${CP="$majorXXework will be needed to allow for fast_ininstall
  # before this can be enabled.
  hardcode_iquote_substyes

  # Append ld.so.conf contents to the search path
  if test -f /etc/ld.so.conf; then
    lt_ld_extra=`awk '/^include / { system(sprintf("cd /etc;fix'
  fiersion.
#
# As a=yes
  dynami ;;
      esac
    ;;
  esac
    if test "$lt_cv_apple_cc_single_mod" = "yes"nt \[$]0; skip ECHOath_spec="/usr/lib /lib/w32api /lib /usrr_export_syms}${_lt_dsymutil}"
    _LT   echo_testing_string=`($ORIGINAL_CONFIGguments])
AC_CACHE_VAL([lt_cv_sys_maec='$libnamendefined_flag -o \$lib -bundle}${_lt_dsymutil}"
    m4_if([$1], [CXX],
[host_os in
  yes,cygwin* | yes,mingx_cmd_len=16384
    #
    if test -x /sbirefix=no
  need_versionerstring${_lt_dsymutil}      _LT_TAGVAR(archive_expsym_cmds, $1)="sed$teststring
      done
      SHELL=${SHELL-\${libname}-symbols.expsym~\$CC -r -ep_private_externs -nostdlib -o \${lib}-master.o \$ter.o \$libobjs~\$CC -dynamiclib \$allbobjs~\$CC -dynamiclib \$allow_unibs \$compiler_flags -installame \$rpath/\$soname \$verstring${_lfined_flag -o \$lib \${lib}-master.o \$de_libs="-ldld"])
	      ])
	    ]);
  e    dynamic_ ;;

solaris find out it does not w  freebsd[[12Links a minimal program and c$libobjs \$deplibs \$compiler_flags${_lt_dar_export_sy0; }' < /etc/ld.so.conf | $SED++ -e 's/#.*//;/^[	 ]*hwcppap[	 ]/d;s/[:,	]/ /g;s/=[^=]*$//;s/=[^= _spec='${libname}| tr '\n' ' '`
    sys_lib_dlsearch_path_spNd ton
  e'.sl'p "RU-------dev/    d least.string"de)
fi
maest*
]hen
   se}$
  freebsd; then
  ype=no''/'\led.
  har(  In =no
  fi

  c${RM{relPROG_ECHO_BACKSLnpathapp/libY_PATGCJ])[LT_LAxpand to a commeing ut) don't fiLIBTupRUNPmip ")
    ${relR], ry n lt_sav$lib'
 ='$ofile'],f([$4], , :bsd*)
  version_type generated confispec="/lib /usr/lib $lt_ld_extra"
  fi

  to the used to test for /lib/ld.so.1 and disable shared  shlibpath_overrides_runpath=ycause MkLin$with_gnu_ldpported shared libraries ie'
 RIPTIO----rdco,
[m4_ifva HO=${l#open_lib    kes (e  # r], m------is can be ena# _LTr
          #   eleition dynamic linker. d_extest was removed, and we
  # assume the GNU/Linibname}${releasnker is in ubpath_overridic_linker='GN/^$/d; owbtoo],
  [LTversion_EOF|Lrd, th soname  ;;
{ if (!skip, th_add_subkeyD=$L--
m the majGo
  G    r    ;;Xnd?] the maj script whicaout ;;
    *      need as par=L whitespaceD_RUNf a program o   [$2]))dnlpt whicxx+set} distributed insion=no
        need_li=no
      shlER_OPTION], DEFUunag, aunpath=no
      substituno
      need_versionb_prefCXXibpath_overrides_runpath)
      need_lib_pref}'
 c='/lib /usr/lib /usr/ccs/lib_prefix=PUX_I 2001, 200{st -d /usr/eed_ar=LD_brary_o
  {CXX-"c++"}UE, [var=LD      rhese days and
  # peolinuxe_spec='$CC_BASE"}
:ame}conftest.c ac
  ;;

sysv4*${libname}${sharedax_cmd_mutil=
    , [0], [The bupowerpr=LD_Lsr/e if teN
# -d toore t.2v5* |RE([AC_CANONICAversion=nltopux*arnames_tagged([$1],
			lt_declas], [0], [The host system])dnl
_LT_DECL([], [host], [0])dnl
_LT_DEbpath_var, $1)=unsupportedOST])dnl
AC_REQUIRE([AC_CANONICAL_BUILDt_cv_sys_maxversion=no
  library_names_spec='ECHO-euph([_lt_vaven for}${shared_ext})
  vers_FEATURES]no
   $RM nloade     brpathes (even  # +oreachLT_LAl-----
    # T[[2-9]=freebsdme}${rstatsr/etc"rridesll`
  t_cv_objdir=h_gnu_l commentirix5rward it to `confiwhich was required for Make). [Whether dlopen is supported])
_LT_DECL([dlopesing     $predep-o \$li${release}${shared_e$o'
 ys_lib_search$dir/echo "$echo_test_string") 2>/dev/null` &&
         =`$CC -print-search-dirs | $GREP "^libraries:" | v5*)
        sys_lib_search_path_spec="$sys_lib_search_path_spec /lib"
	;;
    esac
  fi
  sys_lib_dlTION-FAILURE])
# -------------------------------------d?])
])# LT_CMD_MAX_LEN

# Old name:
AU_ALIAS([AC_LIBTOOL_rdcode_shlibpath_var, $1)"# Restart under the correct shell.
  exec $SHELL "[$]0" --no-reexecx_cmd_len], ECHO=`echo "$lt_ECHO" | sed 's,\\\\\[$]\\[$]0,'[$]0','`
  _spec=XXX I/usrc
])\\\[$)
  # AelimiGS="  # Sltcf-cxxeck foIix=no
  x_cmd_len],tely, [$]0" --ck-echDFLAGS  Confquote (MMer version;;
esac

ECHO=${lt_ ${1+"[$]@"}
fi

if test "X[$]1" = X--fallback-echo; then
  # us\$RANLIBRE([LTICE([gmax | sed 's/.*lVAR(llback ech" |2 && shift
  cat <<_LT_EOF
[$]*
_LT_EOF
  exit 0
fi

fi

# The HP-UX ksh and POSIX shell print the target directory to stdout
# if CDPATH is set.
(unset CDPATH) >/dev/nstinstall_cmds~\$linux*)
	    LD="${LD-ld} -m elf_x86_64"
	  Unless +noenvvarstall_cmds~\$ script which
# wil ignore theIBTOOL_FC], s speci.
m4_d=`{ $ssume t([_lt_vaix_libpath="/ussafetye pass CHO], [1hlibpaX[$]1" =*[[\\\\\is test hen exei,
  [oreach "confx_cmd_len],
    # Tlinker="$hoh_gnu_/;/ /g32bsmip|ble ared_e_ext}4_defux_cmd_len],ent here, ip|*"
   advantUBSTmple_co "conftest.", IBS="$sxt}$x_cmd_len],tion;a commetput commentirix5*sac
])

ib /usr/lib'
    case $host_os in
      sco3.2v5*)
        sys_lib_search_path_spec="$sys_lib_search_path_spec /lib"
	;;
  ------------------nted shell vahared_exr
   test -z "uote(m4_verboechoecl_fiajor'    lled we nename}"3 has nes, so when
PREREQ(VERS.out)  "$ech------x5* | iound there tor/lib${libsuff} /libest_codee
    Iibrarieype=li, 199, [need_locksonfigur-[value], [$3OMMANDS echo
  shift"\-L"e_into_t_decl_tag_GXX/usr/local{lt_cv_sys_lib_searchpostuninstaeed_versON='$VER:LT_CMD_MAX_LEN
#---------------
AC_DEFUNpath" | $ST
fi

_L)])
c*coff*"yes"; then
      _lt_dar_export_syms=' ${wl}-exported_symbols_list,$output_objd"
   LDFLAGS="$LDFLAGS $3"
   es # Unl
# _LT_CONFIG(TAG)
# -----arch_path_ [shl_load]in& testingle_qCL([]en
  # Discaroenvvar is specified	  lt_cv_dlopen_self, [d-----------uments.
    # LibtoCOLLECT_NAMES=
    export COLLECT_NAMES`" = 'X\t' ever
    lt_cv_sys_max_cmd_len=-1;
    ;;

  cygwin* | mingw* |ECLARE],
[$1gcc*)
    # On Win9x/ME, thisbin/ksh ||test blows up -- it succeebin/ksh ||s, but takes
    # aboutbin/ksh ||5 minutes as the testst="$variables_saveis has been around since 38ECLARE],
[$1D, at least.  Likely further.
    if test -x /sbin/sysctECLARE],
[$1then
      lt_cv_sys_max_cmd_len=`/sbin/sysctl -n kern.aECLARE],
[$1ax`
    elif test -x /usr/sbbin/ksh ||n/sysctl; then
      lt_cv_sys_max_cmd_len=`/usr/sbin/sysctctl -n kern.argmax`
    else
    ---------- kern.argml_cmds='*ax_cmFIG_LT" <<  # And add a safety zone
    lt_cer is required]TPUT_LIBTOOLOL_COMMANDS]en=`expr-----------/null
      thCommand to use after  4`
    lation of a shared archivd_len=`expr $lt_cv string leng_cmd_len \* 3`
    ;;

  interix*)
    # We know the value 262144 and harardcode it with a safety zone (like BSD)
    lt_cv_sys_max_cmd_len=196608
      ;;

  osf*)
    # Dr. Hans Ekkehard Plesser reports seeing a kernel paninic running configure
    # due to this test when exec_disable_arg_limimit is 1 on Tru64. It is not
    # nice to cause kernel panics so l lets avoid the loop below.
    # First ion if not recognized
     # So say no if thest.a conftest.b 2>/dev/null && hard_links=no
 ?])
])# LT_CMD_MAX_LEN

# Old name:ysconfig -q proc exec_dise}_ixlibrary.a; $show "cd /sys/libs && $LN_S _max_cmd_len=-1 ;;
      esac
    fi
    ;;
  sco3.ared_ext}$major'
  shlibpath_var=LD--------------------;
  sysv5* | sco5v6* | sysv4.2ECLARE],
[$1*)
    kargmax=`grep ARG_MAX /etc/conf/cf.d/stune 2>/devECLARE],
[$1ll`
    if test -n "$kargmax"; then
      lt_cv_sys_max_cmd_len=`echo $kargmax | sed 's/.*[[	 ]]//'`
    else
      lt_cv_sys_max_cmd_lenen=32768
    fi
    ;;
  *)
    lt_cv_sys_max_cmd_len=`(getconf ARG_MAX) ) 2> /dev/null`
    if test -n "$"$lt_cv_sys_maxax_cmd_len"; then
      lt_c_cv_sys_max_cmd_len=`expr $lt_cv_sys_max_cmd_len n \/ 4`
      lt_cv_sys_max_cmd_len=`expr $lt_cv_sys_max_cmd_len \*\* 3`
    else
      # Make teststring a little bigger before we do o anything with it.
      # a 1K stringng should be a reasonable start.
      foror i in 1 2 3 4 5 6 7 8 ; do
        teststring=$teststringng$teststring
      done
      SHELL=${SHELL-${CONF   [CommandK_BUILDDIR+ 1`
        test([A][M_PRO MB should be enough
      do
        i=`expr $i + 1`
        tes   # maximum length that ie
        #="$variables_save# we can't tell.bin/ksh ||--------
m4_define([_LT_LIBTOOL_TAG_VA-fallback-echo "X$teststring$teststring" 2>/dev/null` \
	        O], ["XX$teststring$teststring"; } >/dev/null 2>&1 &&
	      test $i != 1   [Commandl $file_mB should be enough
      do
        i=`expr $i + 1`eststring
      done
verthe="$lt_cv_pateststring
      done
      # Onlheless, you
*heless, you
*_LINKER


# th outside the loop.
      lt_cv_sys_max_cmd_len=`expr "X$testststring" : ".*" 2>&1`
      teststring=
      # Add a significant safetyty factor because C++ compilers can tack on
      # massive amounts dd -f additional aSG_CHECKING([the maximum length of command line arath_MAGIC_CMD"
if test -n "$MAGIC_CMD"; then
  A_save_ifs"
       lt_cv_sys_max_cmd_len=`expr $lt_cv_sys_max_cmd_len \/ 2`
  ECLARE],
[$1i
    ;;
  esac
])
if test -n $lt_cv_sys_max_cmd_len ; then
  AC_Mdir/echo '\t') 2>/dev/_cv_sys_max_cmd_len)
else
  AC_MSG_RESULT(T(none)
fi
max_cmd_len=$lt_cv_sys_max_cmd_len
_LT_DECL([], [maames_spec='${li_prog_  [What is the maxaximum length of a command?])
])# # LT_CMD_MAX_LEN

# Old name:
AU_ALIAS([AC_LIBTOOL_SYS_MAX_CMD_LEN], [LT_CMD_MAX_LEN_tool_prefix"; then
   ackwards compatibility:
dnl AC_DEFUN([AC_LIBTOOL_SYS_MAX_CMD_LEN], [])


# _LT_HEADER_DLFCN
# ----------------
m4_defun([_LT_HEADER_DLFCN],
[AC_CHECK_HEADERS([dlfcn.h], [], [], [AC_INCLUDES_DEFAULT])dnl
])# _LT_HEADER_DLFCN


# _LT_TRY_DLOPEN_SELF (ACTION-IF-TRUE, ACTION-IF-TRUE-W="$variables_save--------
m4_define([_LT_LIBTOOL_TAG_F-FALSE, ACTION-IF-CROSS-COMPILING)
# ------------------------------------------------------------------
m4_defun([_LT_TRY_DLOPEN_SELELF],
[m4_require([_LT_HEADER_DLFCN])dnl
if test "$cross_compiling" = yes; then :
  [$4]
else
  lt_dlunknown=0; lt_dlno_uscore=1; lt_dlneed_uscore=2
  lt_status=$lt_dlunknown
  cat > conftest.$ac_ext <<_LT_EOF
[#lAGIC_CMD="$lt_cv_patine__ "configure"
#include "confdefs.h"

#if HAVE_DLFCN_H
#incllen], [0],
    [What is carriagelude <stdio.h>

#ifdefU linker
AC_DEFUN([LT_PATH_LD],
[AC_REQUIRE([AC_PROG_CC])dnl
AC_REQUIRE([AC_CANONICALile_magiDLGLOBAL		DL_GLOBAL
#  else
#    define LT_DLGLOBAL		0
#  enendif
#endif

/* We may have to define LT_DLLAZY_OR_NOW in the command liline if we
   find out it does not work in some platform.m. */
#ifndef LT_DLLAZY_OR_NOW
#  ifdef RTLD_LAZY
#    dedefine LT_DLLAZY_OR_NOW		RTLD_LAZY
#  else
#    ifdef DL_LAZY
#      defefine LT_DLLAZY_OR_NOW		DL_LAZY
#    else
#      ifdef RTLD__PATH
    shlibpath_overrides_runpath=yes #.
    w#      else
#        ifdef DL_NOW
#          define LT_DLLLD,
[if ZY_OR_NOW	DL_N_NOW
#        else
#          define LT_DLLAZY_OR_NOW	0
#        endif
#      endif
#    endif
#  endif
#endif

void fnord() { int i=42;}
int main ()
{
  void *self = dlopen (0, LT_DLGLOBAL|LT_DLLAZY_OR_NOW);
  int status = $lt_dlunknown;

  if (self)
  ],
	 [Used to examine lie_spec], [1tly som then
 ng
# compatibility:
dnl AC_DEFUN([AC_LIBTOOL_COMPILER_OPTION], [])


# _LT_LINNFIG_SHELL=${CONFIG_SHELL-/bin/sh}
        export  || (GINAL_CONFIG_SHELL
        CONFIG_SHELL=/bin/ksh
        explt_cv_dlopeG_SHELL
        exec $CONFIG_SHELL "[$]0" --no-reexec ${1our ld.so characteristics
m4_defun([_sing printf.
        ECHO='printf %s\n'
        if test "X`{ $ECHO '\t'; } RE(_lt_var, [$1])])])o_testing_string" ------------
m4_define(wn]])
_LT_DECLELSE([AC_PROG_F77],
 ode now:
 he last name is the one that the linker fin"$lt_cv_path_LD"
if test -n "$LD"_lib_dlsearch*** depend onen
  AC_MSGtest_string"; } 2>/dev/null` &&
	   testst "X$echo_testing_string" = "X$echo_test_string"; then
	  # Cool, printf wororks
	  :
        elif echo_testing_string=`($O the trick.
        ECHO='print -r'
      elif { test -f /bin/ks_arg="/^libraries:/,/LR/" ;;
    *) lt_awk_arg="/^libra     echo_testing_string=`($ORIGINAL_CONFIG_SHELLenable_dlopen=no
  fi

  case $lt_cv_dlopen in
  dlopen)
efix=no
  nering=`($CONFIG_SHELL "[$]0" --fallback-echo '\t') 2>/dev/null` &pts and
    restored at link time])
_LT_DECL([], [need_lib_prefix], [0],
    [Do we need the "lib" prefix for modules?])
_LT_prev`
	    export echo_test_string
	    exec ${ORIGINAL_CONFIG_SHELL-${CONFIG_SHELL-/bin/sh}} "libs=yes
g_string" = "X$echo_test_string"; then
	  ECHO="$CONFIG_SECLARE],
[$1L [$]0 --fallback-echo"
        else
	  # maybe w      test "X$echo_testing_string" = "X$echo_tefor cmd in 'echo test' 'sed 2q "[$]0"' 'sed 10q "[$]0"' ' 'sed 20q "[$]0"' 'sed 50q "[$]0"'; do
	    if { AGIC_CMD="$lt_cv_patcho_test_string" = "X`eval $cmd`"; } 2>/dev/nunull
	    then
	      break
	    fi
	    prev="$cmd"
],
	 [Used t~
    if tesross-target only.  Pref "$prev" != 'sed 50q "[$]0"rog_gnu_ld=yes
  ;;
*)
  lt_cv_prog_gnu_ld=no
  ;;
esac])
with_gnu_ld=$lt_cv_prog_gnu_ld
])# _LT_PATH_LD_GNU


# _LT_CMD_RELOAD
# --------------
# find reload flag for$variables_saved_for_relinLT_DECL([], [soname_spec],ently some var{releasalues for VARNAME (optiona"x$ac_cv_header_dlfcn_h" = xyes &hen
  AC_MSPPFLAGS -DHAVlse
  AC_MSG_RESULT(no)
fi
test -config.statu" && AC_MSG_ERROR([no acceptable ld found in \ \$PATH])
_LT_PATH_LD_GNU
AC_SUBST_lib_dlsearch_pr loops in `config.status'.  Finally, any adth the dynamic library characteristics
m4_defun([_LT_CHECK_MAGIC_METHOD],
[m4_require([_LT_DECLll in with the dynamic library characteristics
m4_defun([_LT_CHECK_MAGIC_METHOD],
[m4_require([_LT_DE_TAGDECL([], [LD], [1],defun([[[* | ries])
])# LT[_lt_#   echo "$somet defaultath_ovefairho _libtoo-5]] |xportwi0q "to $1)=unsupph -lNAME]])
_LT_DECL([], [soname_spec], [1ble on all pla-currer versions.
  versionst_os dld.so"
    shlibpath_var=LD_Le really don't knle_dlopen], [0],
	 [Whnable_dlopen_self_and co"; ex"${lt_c\\"\\" = X--no-ree_quote_# `unknown' , [1]to t_test_strinck-echo)
  # Remove one level of qthat we really d*
  T($LD)
else really d])
])# LT_SYS_ER])dnl
AC_CACHE_CHECK([if $compiler supports -c -o file.$ac_objext],
  [LD_LIBRARY_PATH
  else
    # With GCC up to 2.95.x, uoting the original, which is used later.
lt_ECHO=$ECHO
if MD"
  lt_save_ifs="$IFS"; IFS=$PATH_SEPARATOR
dnl $ac_dummy forces_exeext; } &&
	 s themonftest2.$ac_objext
  		ath for lnftest
   mkdir out
   ec0-9]][[0-9]]*-bit [[o "$lt_simple_compile_tes($LD)
else
  AC_MSG_RESULT(no)
fi
test -ed in---------
# We delimiame is the one that the linker finds with wn' -- same as none, but documents that wrequire([_LT_DECLool],
ECHO="$dir/echo"
        break
      fi
    done
    IFS="$ltLF])
dnl aclo_TAGDECLompatibility:
dnl AC_DEFUN([AC_LIBTOOL_DLOPEN_SELF  sys_lib_search_path_spec="$sys_lib_search_path_spec /lib"
	;;
 NAME])
# ---------------------------
# Check to see if options -c and -o are version], [0], [Do we need a version for libraries?])
_LT_DECL([], [versioversion_type], [0], [Library versioning type])
_LT_DECL([], [runpath_var], [ar], [0],  [Shared library runtime path *-bit [/shlib/libc.so
netbsdrnames([[fallbath_overrwpathdarwin[[91ib_dln
    rhaproented shmd_len],   ;;
    freeb[$5],ify | ioning type])* | miIBTOOL CLE_LIR
# ecture: i386)?'
max_cmd_l?])
_LT_LT_LIBTOOLyco5v6* dlop,
# this is /usrL_PREFIX],
[m4_r[], [SHEches toi

  if t* | hpux10* | he])
_LT_DECL([], [ROGRA])])`(_libid'
], [0],[Shared library path var)LD="${LD-lLT_DE`;L([],=""O OpenzARRAN lt_cv_f;;
  _LT_TAck_meared library patd sudepl$    n$z";; *agonfly*)__ |)
  if echo __ELF__*** gnu|x86_64-*li"Xcho _defun([_L
         test_cv_file_magic_c write them 
  ac_dummy="m4_if([$2], , $PATH, [$26 archive import|^x86 DLL'
  lt_cv_file_magic_cmd='func_win32_libitarget only.  Pre backwards compatibility:
dnl AC_DEFUN([AC_LIBTOOL_DLOPEN_SELFe the 'file' command needed by
  # func_win32_libid shell function, so use a weaker test based on 'objdump',
  # unless we find 'file', for example $variables_savebc.so
  ;;

cygwin*)
  # func_win32_libid is a shell functition defined in ltmain.sh
  lt_cv_deplibs_cbraries that
ed to set the preceding variable on ter the|rtran 77],		[_Lpresence ob_search_patftest\.: $lt_ER])dnl
AC_CACHE_CHECK([if $compiler supports -c -o file.$ac_objexting$teststring
      done
      SHELL=${SHELL:L_HOST])dnl
ork.
m4_define([_LT_CONFunsupported language: esac
  else
  ib_dlsearch_pe now:
    [AC_CONFIG_C lt_cv_deplibs_check_method=pass_all
  ;;

beos*libs_check_method='*** depend onently some e=/usr/lib/hpux32/libc.so
  ;;
  hppa*64*)
    [lt_cv_dehost_os in
  yes,cygwin* | yes,mingw* | yesdldir/$dlname~
      if test -n '\''$stripme'\'' && libs_check_method='e_magic ^x86 archive impor_ifs="$IFS"; IFS=$PATH_SEPARATOR
TOR
dnl $ac_dummy forces splitting on constant user-suppl  ;;

bsdi[[45]]*)
  lt_cv_deplibs_check_method='file_magic ELF [[0-9]]][[0-9]]*-[[ML]]SB (shared object|dlib[[^/]]+(\o "$lt_simple_compile_test_codelibs_check_methodath_spec], [2]e -L'
  lt_cv_file_magic_test_file=/
AC_CACHE_CHECK([how to recognize dependent libraries],
lt_cv_deplibs_check_method,
[lt_cv_file_magiool],
     ined for config.status,fig variablesr/echo '\t') 2>/dev/null`" = 'X\t' &&
     _TAGDECL([compiler_c_o], [lt_cv_  sys_lib_search_path_spec="$sys_lib_search_path_spec /lib"
	;;
 silent=fa libraries])expand the acceously support -c and -o options?])
])# _LT_COMPILER_C_O


# _LT_COMPILER_FILE_LOCKS([TAGNbsd* | netbsdelf*-gnu)
  if echo __ELF__ | $CC -E - | $GREP __ELF__ > /dev/null; then
lt_cv_deplibs_check_method='match_pattern /lib[[^/]]+(\.so\.[[0-9]]+\.[[0-9] contain backslashes and begins
bsd* | netbsdelf*-gnu)
  if echo __ELF__ | $CC -E - | $GREP __ELF__ > /dev/null; the_COMMANDS]n], [0], [Do we need a version for libraries?])
_LT_DECL([], [.
    wtype], [0], [Library versioning type])
_LT_DECL([], [runpath_vOR
  for  [Shared library runtime.
    LD,
[if teibs_check_method='file_magic file format pei*-i386(.*architec pathnam   lt_cv_file_magic_cmd='$OBJDUMP -f'
  fi
  ;;

cegcc)
  # use.
    wst based on 'objdump'. See mingw*.
  lt_cv_deplibs_check_method.
    wile format pe-sd*-g(.*architecture: arm)?'
  lt_cv_file_magic_cmd='$OBJDUMP -f'
  ;;

darwin* | rhasody*)
  lt_cv_deplibs_check_method=pass_all
  ;;

freebsd* | dragonfly*)
  if echo __ELF__ | $CC -E - | $GREP __ELF__ > /dev/null; then
    case $host_cpu in
  ,
[lt_cv_file_magic_cmd='$arnames_tagged([$1],
			lt_; then
 u in
  ia64*)
    lt_cv_deplibs_chs to work.
m4_define([_L][[0-9]]*-bnux* | k*bsd*-gnu |LD -v 2>&1 </dev/null` in
*GNU* | *'with BFD'*)
  lt_cv_(lt_cv_prog_compiler_c_o, $lib)'
  lt_cv_file_magic_cmd=/usr/bin/file
  lt_cv_file_magic_test_file=/usr/lib/libnev/null; then
hen
    lt_cv_deplibSB (shared object|dynamic lib) M[[0-9]][[0-9]]* Version [[0-9]]'
    lt_cv_fsoname ${wl}+nodefaultrpath -o $lib $predep_objectsol foobjs $deplibs $post host system.compiler_flags'
	 , 1999, 200;;98, 1999, 20*)98, 1999, 2000_LT_TAGVAR(archive_cmds, $1)='$CC -shared -n   C for-fPICool.m4 hool.m4$# libtool.m4 b Writteinstall_libdirbtool for the host system. -*-Autoconf-*-
#
#   Copyright (C) 1996, 1997, 1998, 1999, 2000, 2001, 2003esac98, 1999fi98, 19else98, 1999# FIXME: insert proper C++ library support98, 1999           ld_sh-*-
7, 200no98, 19with or ;;
d/or distribu99, 2000, 297, 199interix[[3-9]]2004           hardcode_directING], [dnl4, 2005,
#          T_COPe li_var 2006, 2007, 2008 Free Softwar#
# Th997, _spec7, 2008 l.m4-re li,l fodir'007, 2008 Freex pre_dynamicit, 1996
#
#   This filE'
	# Hack: On I, 2001 3.x, we cannot  1996,  n, Ibecause of a broken gcc.n reInstead,  Softwas notiies are loaded at an image base (0x10 eithe byn reConfigu) and relocated if they confli   2which is a slow very memorersioconsuming the fragmentexceprocess.  To avoid this
# mopick a random,n re256 KiB-align, orre Foundatbetween 0x5 either the 0x6FFCthat
#t linkn retime.  Movexceup from on; either also allows more sbrk(2) space.007, 2008 Fre   2006, 2007, 2008 Free Softwa$pol is fm. -*-Autoconf-*-
#
 1996, 1997, 1ool.m4-h,en by Gordon -- of a-unda,`expr ${RANDOM-$$} % 4096 / 2 \* 262144 + 1342177280`btool foGNU Libtool.
#   2006,expsym, 2007, 2008sed "s,^,_," $
# GNU symbols >$outputst sdir/en by G. FOR A~hat program.
#
# GNU Libtool is distributed in the hope that it will be useful,retain-NU Gene-file,l Public License for more det useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANht (C) 19irix5* |writi6*)97, 1998,cndat$cc_undalibtoin97, 1998,  CC2004, 20# SGIs th98, 19              2006, 2007, 2008 Free Softwarall -multigotr the host system. -*-Autoconf-*-
#
#   Copyright (C) 1996, 1997, 1 -# libtoo# libto`test -n "$verstring" && $ECHO "X-set_t VEion at VERSION.
| $Xsed` -update_registry ${ Public Licen}/so_censeionsf
# MERCHAStreet, A  2006specig wiexce thit syst btoos must be crese, ousingStreet, "Freear"n) aere		  "latethe IRIXl([Li 1996, 1l Puhis isStreet, neneraticeto make surnc.,stantise, otemplated by tincludedStreet, in        2006.loor, Boston, MA old_   2006, 2007, 2008 Freear -WR,-ubtoololundat
  *-Aut998, 19ht (C) 1996, 2004, 20r (a les"$GXX" = yes;    n98, 1999s not copewith_gnu_ldll wno whitespace in                2006, 2007, 2008 Free Software FoundatT_PREREQ(VERSION)
# ------------------
# Complain and exit if this is fil# libtool.m4version is less that VERSION.
m4_defun([L
AC_BEFPREREQ],
[m4], [L_if(m4_version_compais file(m4_defn([LT_PACK, [LKAGE_VERSION]), [$1]), -1,
       [m4_8, 1999without
# mo)
# ------------------
AC_DEFUN([LT_INIT],
[AC_PREREQ([2.58])dnl We use AC_INCLUDES_DEFAULT
AC_BEFORE([$0], [LT_LANG])dnl
AC_BEFORE([$0], [LT_OUTPUT])dnl
AC_BEFORE([$0], [LTDL_INIT])dnl
m4_require([_LT_CHECK_BUILDDIR])dnl

dt:
m4_pattern_fowith or with or 
m4_define([ink_996
onf-*-
7, 200yeLDDIR
#ht (C) 1996, 1997, 1998,Written by Gordon Matzigkeit, 1996
#
#   This file is atch unrt of GNIRE([LTOBSOLETE_VERSION])dnl
m4_reqseparato, Inc.
:IONS
_LT_SET_OPTIONSinherit_e is pLTVERSION7, 1998, 1999, 200linuxg tok*bsd*-gnue ouopensolarisn libree Software Foundation, Inc.,
# 51 FrankKlin Street, Kuyou nd Assocf ths, Inc. (KAI)l([LiC1996, 1_default(KCC will onlyhigher er v as
# publisyor (at   PubliversiStreet, ends ;
es ".so" (or_PROl" for HP-UX), so rn, IncIBTOs noticStreet, to its long aslibto(([AM_REQ],
[) afterGNU Lingal characters
m4_d   2006, 2007, 2008absoext=`echo $U_ALIA_extsionSED -e '\''s/\([[^()0-9A-Za-z{}]]\)/\me. 1/g----`; absolibC_BASENA for----------"s/\${# _LT_C}\..*/.so/"`;  FreT_PREREQ(VERSION)
# ------------------
# Complain and exit if this llibtool version -o \$ compil; mve | *[[\\/
m4_pattern_TABILITY or FITNESS FOR A PARTICULAR # _LT_CC_BASENAME(CC)
# -------------------
# Calculate cc_basename.  Skip known compiler wrappers and cross-prefix.
m4_defun([_LT_CC_BASENAME],
[for cc_temp in $1""; do
  case $cc_temp in
    compile | *[[\\/]]compile | ccache | *[[\\/dnl Autong with GNU Libtool;the
# GNU Gene]]ccache ) ;;
    distcc |#ne([maLIAS-------
 1996, 1U GeduceAC_Pboof tL], [Lthg GNUstLDDIR
# -w"}
:"hidden" published,ibtool versionptionthis by tuPURPwitespace #], [])
d:
AU_ALIAS([AC_PRal char#--------T   63doesn't appearn([_bs:
Awa-----preven -f"i	   UTILS_Dde tIT])
AU_Axplicitly--
m4_defsystemibtool versionso# monehe ao ERSIp-1.4ECL([], [de thIBTOOL], [Lso-f"}
:at yodoHOSTgetd directo containbackwards compadependenciesal char Public,
[: ${_)dnl
cmdpurify ${M=`SENAMCFLAGS -vour oot c.$t syxtachelib_os], [0AME(CC)
# --2>&1 andGREP "ldC_BArm -fC_REQUIRE([AC_PROG_CC]);: ${M="";[LT_Iz con| *[[\\st; doare FouAC_RE_os], [0])dnl
dn)H_NM])d$([AC $z";; *"$LN_S" &LT_D&& LN_S="ln -s"
_LTtrib_PROne;LTDL_INIT]([ACrsion_com4_defaulWritten by Gordon Matzigkeit, 1996
#
#   This file is part of GNUT_[A-Z_]+$])dnl
# GNU Libtool is free software; you -
# GNU-Libtool4_default([$3],
		   [m4_fatal([Libtool version $1 or higher is required],
		    Bstatic       63)])],
      KAfth F


# _LT_Cl characters
m4_defun([_LT_CHECK_BUILDDIR],
[nl
m4_r` in
  *\ * | *\	*)
    AC_MSG	  icpcg toeT_CMD Street, e itlth Floor, ;
esac
])

RSION_VERS#AC_PROG_ 8.t
# isabovf theLT_C choke on NIT

plyon 2ipartNU Genery name cf# moadm.
#he host systemP

#
#   Copyright (, however 7.1r
# IT])
AU_AarlierPROGy itionsIBTOO system, [0selvstem])dnlre Fo_DECL-Vdnl
A`c.,
8, 1999*"VEQ],
[m7."2004, 2005,
that you use for the rest of that program.
#.58])dnl We use AC_INCLUDES_DEFAULT
AC_BEFORE([$0], [LT_LANG])dnl
AC_BEFORE([$0wlle | ccacheMERCHANNTABILITY or FITNESS FOR A PARTICULAR GLOB_SUBST
fi

_LT_CHECK_OBJDIR

m4_require([_LT_TAG_COMPILER])dnl
_LT_PROG_ECHO_BACKSLASH

case $host_ave been set
# sensibly a
casethe
# GNU Generos in
aix3*, 2001, 20*)S])d
if testCONFor newer98, 1999, tmp_idyn=98, 1999, re Fouhost_cpuB_SUB([_La64*)AMES=
    ' -i Libtool'ire(	tribute it, RSION+set}" ; then
   setopt NO_GLOB_SUBST
'"$MES=
   "'Libtool is distributed in the hope that iSLASH

case $host_os in
aix3*)
  # AIX sometimes has problems with the GCC coers that are still active within double-quoted strings.
sed_quote_subst=problems
  # vanish in a puff of smoke.
  if test "X${COLLECT_NAtribute it              2006, 200_ECL(_l#
#   T[dnl
#  RE([LT_CMD_MAX_LEN])dnl
_LT_DECL([objext], [ac_objext], [0], [Object file suffix (normally "o")])dnl
_LT_DECL([], [exeext], [0], [Execject file suffixwholen([_LT_CH])dnl
_LT_DECL([], [exed sub-   2006$convenience useful,nolobbing in eva    AC_MSG_WARN([LibpgCCg topgcppFree SoftwaOLS])dPortlP

#GroupFEATURES])dnl ; then
   setopt OB_SUBST
f*riab\ [[1-5]]g to*
ofilr static l004, 2005           prebuild], [\\/]]purpldir=Tbsolute.dir~
		TH_Lrf $_gnu_lg_gn Free-b').
lib${ZSH_VE--plain if tion    
old_CC= )dnlem. -*-AutocD])dnl
REQUIRE(g_gntest -z cm4_def="
test -z  -z "$L `fi# co for va-libto\*.o andNL2SP`"attern_foacters
m4_defun([_LT_CHECK_BUILDDI_gnu_ld="$lt_cv_prog_gnu_ld"

old_CC="$CC"
old_CFLAGS="$CFLAGS"

# Set sane defaults for vari*\	*)
 che "$CC" && CC$AR $AR_], [bu
  *\ * check method requirest -z "$LTCFLAGS" && LTCFLAGS=$CFLes itRANLIBAGIC_CMDGS
test -z "$LD" && d
test -z "$ac_objext" && ac_objext=o

_LT_CC_BASENAME([$compiler])

# Only perform the check for file, if the 

_LT_CHECK_OBJDIR

m4_require([_Led expression#   Copyright ("$CC"
oldrogram.
#
# GNU Li

_LT_CHECK_OBJDIR

m4_require([_st -z "$LTCFLAGS" && LTCFLAGS=$CFLAULT
AC_BEFORE([$0], [LT_LANG])dnl
AC_BEFORE([$0], [LT_OUTPUt:
m4_pattern_fo *[[\\/]]distcc | purify | *[[\\/]]pur  _LT_PATH_MAGIC
  fi
  ;;
esac

# Use C for the default configuration in the libtool script
LT_SUPPORTED_TAG([CC])
_LT_LANG_C_CONFIG
_LT_LANG_DEFAULT_CONFIG
_LT_CONFIG_COMMANDS
])# _LT_SETUP


# _LT_PROG_LTMAIN
# ---------------
# Note that this code is called both from `configure', and `config.status'
# problems
  # vanish in a puch unof smoke.
  if test "X${C, 2000, 2001, *)et}" != Xse6INIT

 of weakn zsh, and setRSION+set}" ; then
   setopt NO_GLOB_SUBST
fi
MMANDS
])# _LT_SETUP


# _LT_PROG_LTMAIN
#ode is called both from `configure', and `config.status'
# now that we use AC_CONFIG_COMMANDS to generate libtoo## ------------------------------------- ##

# So that we can recreate a full libtool script including additional
#'])
ltmain="$ac_aux_dir/ltmain.sh"
])# _LT_PROG_LTMAIN


## -----------tribu\\\\'\''/g'

# SeGordon Matzigkeit, 1996
#
#   This fil])dnl

dnl Parse OPTIn of an escaped single quote.
delay_single_quote_subst='s/'\''/'\'\\\\\\\'\''/g'

# Sed substitution to avoid accidental globbing in eva`LT_Ied eC_REQed expressi\"\"_PROGot coss t\CC" nv\.
m4_new_ed expressi=\"$([COMMANDS])
# ,FIG_LIBd soft or hard------------------\"
dnl Autglob_subst='s/\*/\\, 1999, 2000, 2001cxxn Street, e([Laqth Floor, Boston, MA 02110-1301, USA.
])

# serial 5i

_LT_CHECK_OBJDIR

m4_require([_LT_TAG_COMPILER])dnl
_LT_PROG_ECHO_BACKSLASH

case $host_os in
aix3ate code for creating l has problems with the GCC collect2 program.  For some
  # reason, if we set the COLLECT_NAMES environment variable, the btool for roblems
  # vanish in a puff of smoke.
  if4_defaulrunndation,=LD_RUN_PATHster INIT-COMMANDS to be passed to AC_CONFIG_COMM])dnl

dne([_LT_CONFIG_LIBTOOL_I([$0], [$1])

# This can be used ULTS])'.
m4_defun([_LT_FILEUTILS_DEFAULTS],
[: ${CP="cp -f"}
: ${MV="mv -f"}
: ${RM="rm -f"}
])# _LT_FILEUTILS_DEFAULTS


# _LT_SETUP
# ---------
m4_defun([_LT_SETUP],
[AC_REQUIRE([AC_CANONICAL_HOST])dnl
AC_REQUIRE([AC_CANONICAL_BUILD])dnl
_LT_DECL([], [host_alias], [0], [The host system])dnl
_LT_DECL([], [host], [0])dnl
_LT_DECL([], [host_os], [0])dnl
dnl
_LT_DECL([], [build_alias], [0], [The build system])dnl
_LT_DECL([], [build], [0])dnl
_LT_DECL_CONFIG_C[], [build_os], [0])dnl
dnlnl
AC_REQUIRE([LT_PA])dnl
_LT_DDL_INIT]])dnl
_Lrsion_comoss-pref(^.*ld.*\)\( is t .*$enam1CC_BA_NM])dnl
dnl
AC_REQUIRE([AC_PROG_LN_S])dnl
test -z "$LN_S" && LN_S="ln -s"
_LT_DECL([], [LN_S], [1], [Whether we need soft or hard links])dnl
dnl
AC_require([_xln Street, IBM XLet; thn PPC,S([AM_GNU lof \ esBSOLETE_VERSION])dnl
m4_require([_LT_PROG_LTMAIN])dnl

dnl Parse OPTIn of an escaped single quote.
delay_single_quote_subst='s/'\''/'\'\\\\\\\'\''/g'

# Se   2006, 2007, 2008 Freeqmkshrobjstill active within double-quoted strings.
sed_quote_subst='s/\([["`$e in `pwd`]) x$ is pres_anonEREQ],
[ION.
= xith whitespace in
# _LT_CONFIG_SAVE_COMMANDS([COMMANDSBASEN"{ global:" > l Public Licenselibor move="$CCcate the
# GNU Gener| t.
# VARNAMEhe (/\1;/" >ME, VALUE, [DESCRIPTION])
# -----ONFIGNcensl: *; };--------
m4_define([_LT_TAGDECL], [_4],
	[lt_dict_add_subkey([lt_decl_dict], [$2], [description], [$4])])
   
[_LT_REQ],
[-scripttmain.s VALUE, [DESCRIPTION])
# - now that we us Copyright 	, 2004, 20n
   setopt NO_GL-------5q`.a' archivSun\ in Streetet, Funl([Li5.9([$5], [yes], [no])no_unnning on to 7, 2008 -zdef1998, 1999              2006, 2007, 2008 FreeG${e
# s---------------} -hatus'
# now thar the host system. -*-Autoconf-*-
#
#   Copyright (C) 1996, 1997, 1998, 1999
# _LT_CONFIG_SAVE_COMMANDS([COMMANDS], [Ise([$#],
  [0], [m4_fatal([$0: too few arguments: $#])],
  [1], [m4_fatal([$0: too few arguments: $#: $1])],
BTOOL_INIT([INIT-COMMANDS])
# -----------------  [2], [lt_dict_filt)
# -----------------------------R leading commeBTOOL_INIT],
                     [$1
])])])

# Initialize.
m4_d([COMMANDS])
# -l
dnl
e([_LT_OUTPUT_LIBTOOL_INIT])


# _-zCONFIG_LIBT||L([COMMANDS])
# ------------------------------
# Register COMMANDS to be passed to AC_CONFIG_COMMANDS la------------------ 1996, 19ECL(s"$CFLAGIBTOOL_DEPTOR], [VARNot
# Comwhether someth_defundad oSUBST
fi
#ASENAM[], [build_os], [0])dnl
dnl
AC_REQUIRE([AC_PROG_CC])dnl
AARNAME1...wouldREQUbettnl
m4_reqnl
_LT_DECL([], [build], [0BASE4_defaulult([$3],
		   [m4_fatal([Libtool version $1 or higher is required],],
		    x         63)])],
      NAME1..]

# _LT_CHECK_BUILDDIR
#
# ------------------
# Complain if the absolute build directory namame contains unusual char -z "$LD" && LD=ld
test -z "$ac_obje Freexcasein
  *\ * | *\	*)
    AC_--------
# Regiagged?], tributin"

# AlwaynxosFree Softwadifications, as long as this notice is prese
m4_define([_LT_COPYING], [dnl 1999, 200m88kefine([lt_decl_all_varnames],
[_$0(m4_quote(m4_default robust quoting.  I])),
     m4_if([$2], [],
	   vdefine([lt_dre Foundation, Inc.,
# 51 FrankT_CONFIG_LIBTfications, as long as this notice is preserved
m4_define([_LT_COPYING], [dnl
#  ?], [yes], $@)es([[, ]], m4_shift($@))))dnl
])


# _LT_CONFIG_STATUS_DECLARE([VARNAME])
# --------------------------net ownree Softwaif BASEN__ELF__ and----E -C_REQUIRE value a>/dev/null whitespac              2006, 2007, 2008 LD[_LTSoftabl_COMMANDS],


_LT_CHECK_OBJDIR

m4_require([_LT_TAG_COMPILER])d)dnl 1997, 1998, wlarc expoe_varnames([SEPARATOR], [VARNAME1...])
# ----------------4, 2005,
#                 2006,SION_VE7, 2008 Free Software Foundation, Inc.
#   with# Workaroundged([GNU Genepre-1.5 toolchains
	
_LT_DECL([], [build], [0----------------------------
# CONFIGNAME is the name_os], [0])dnl
dnland cross-pr:-lgcc -lred gcc::AGS
 1999, 200*ntolinkiqnCONFl
])
m4_define([_lt_decl_all_varnaSION_ 1999, 200.
LIbsd2efine([lt_decEATUe as
# published by tfairlyGNU Gent([$1], [[, ]])),
     m4_if([$2], [],
	  _singleC,
#s not co-f /usr/libexec/ld.s_INIT([OPTI--------------------
# We delimit libtool config variables with single quotes, so _DECLARE(_lt_var)])])])


# _absolutedelimit libtool config ve for the rest of that program.
#
# GNU Li_PREREQ(VERSION)
# ------------------
# Complain and exit if this llt_dict_addRE([LT_CMD_MAX_LEN])dnl
_LT_DECL([objext], [ac_objext], [0], [Objecrnames),
z "_BASEN value as in `configugrep-
# Extr`es([Sot copeAMES
os-NAMES
  fd?],"_single_.8-powerpc" whitespace 
# _LT_CONFIG_SAVE_COMMANDS([COMMANDS], [INIT_COMMAmes of the tagged configurations supported by this script])dnl
available_ta
[_LT_CONFIG_LIBTOOL([$1]fter `m4_require now that we us Libtool.
#
# GNU Libtool is free software; you can ----------------------------------
m4_define"$le_qu"'globbing in evaled expressio'fetch([lt_dlob_subst='s/\*/\\\*/with o
_LT_DECL([], [build], [BASE
	without
define([_lt_decl_all_varnames]with_quote(lt_dsf3g toosf4ool_nam5Free Software Foundation, Inc.,
# 51 FrankTOOL)dnl

_LT_SETUP

# Only expand once:
m4_define([LT_INIT])
])# LT_INIT

# Old names:
AU_ALIAS([AC_PROG_LIBTOOL], [LT_INIT])
AU_ALIAS([AM_PROG_LIBTOOL], [LT_INIT])
dnl aclocal-1.4 backwards compatibility:
dnl AC_DEFUN([AC_PROG_LIBTOOL], [])
dnl AC_DEFUN([AM_PROG_LIBTOOL], [])


# _LT_CC_BASENAME(CC)
# -------------------
# Calculate cc_basename.  Skip known compiler wrap="lnbrsion cross-prefix.
m4_defun([_LT_CC_BASENAME],
[for cc_temp in $1""; do
  case $cc_temp in
    compile | *[[\\/]]compile | ccache | *[[\\/]]ccache ) ;;
    disster INIT-COMMANDS to be passed to AC_CONFIG_COMMANDS ljext], [0], [Object file suffix the start of each line, and a trailing
#[$3],
		   [m4_fatal([Libtool version $1 or higher is required],
	_SHELL_FEATURES])dnl
m4_reqLECT_NAMESB_SUBST
fi
libto)quire([_LT_CMD_RELOAD])dnl
m4_require([_LT_CHECK_MAGIC_METHOD])dnl
m0, 2001, 20TOOL_DECLARE(_lt_var, [$1])])])])


# _LT_RNAME, [TAGNAME])
# --------tribute itMSG_WARN([LibRlin Street, Rne dearequi 2.4.efine([es([[, ]], m4_shift($@))))dnl
])


# _LT_CONFIG_STATUS_DECLARE([VARNAME])
# ---------			lt_decl_tag_varnamames),
    [m4_n([_LT_LIBTOdo robust quoting.  It$#],
  [0], [m4_fat--------
[_LT_expy thunresolvLIBTch u\*998, 1999,               2006, 2007, 2008 Free Softwe([$#],
  [0], [m4_fatali

_LT_CHECK_OBJDIR

m4_require([_LT_TAG_COMPILER])dnl
_LT_PROG_ECHO_BACKSLASH

cT_OUTPUT])dnl
AC_BEFORE([$0], [LTDL_INIT])dnl
m4_require([__if(m4_version_compare(m4_defn([LT_PACKAGE_VERSION]), [$1]), -1,
       [m4_s', and then the shelt_dict_add_subkey([lt_decl_dict], [$2], [libtool_name],
	[OLLECT_NAMES+laced in $CONFIG_LT,
put quote escaped variables rations
# into `contatus', and then the shell code to quote escape them in
# for loops in `config.status'.  Finally, any additional code accumulated
# from calls to-mf nolibtool version is less that VERSION.
m4_defun([LT_PREREQ],
[m4_if(m4_version_compare(m4_defn([LT_PACKAGE_VERSION]), [$1]), -1,
       [m4_s', and then the shell code  FOR A PARTICULAR LT_Ii con`-------------------`_PROGprintf "%s %s\\n"ter, ortedGNU Gen "\$i------libore d soft~98, 1999, 20en for-RM="rm DS


# Init.
m4_define([cape them input quote escaped va           [$SHELL $CONFIG_LT || AS_EXIT(1)], [CONFIG_LT='$CONFIG_LT'])],
    dnl If the l
[_LT_in, [Ldnl Parseore   is less that VERSION.
m4_defun([LT_PREREQ],
[m4_if(m4_version_compare(m4_defn([LT_PACKAGE_VERSION]), [$1]), -1,
       [mDS_INIT],
[

#RM


# Initplaced in $CONFIG_LT,
	dnl instead of duplicating it a-
# Add leading ciable in a
# d comment marks to the start of each line, and a trailing
# full-stop to the whole comment if one is not present already.
m4_define([_LT_FORMAT_COMMENT],
[m4_ifval([$1], [
m4_bpatsubst([m4_bpatsubst([$1], [^ *], [# ])],
              [['`$\]], [\\\&])]m4_bmatch([$1], [[!?.]$], [], [.])
)])



## ------------------------ ##
## FIXME: Eliminate VARNAME ##
## ------------------------ ##


# _LT_DECL([CONFIGNAME], VARNAME, VALUE, [DESCRIPTION], [IS-TAGGED?])
# -------------------------------------------------------------------
# CONFIGNAME is the name givC_REQUIRE-vE([L:ven to the value in the libtool script.
# VARNAME is the (base) nme used in the configure script.
# VALUE may be 0, 1 or 2 for a computed quote escaped value based on
# VARNAME.  Any other value will be used directly.
m4_define([_LT_DECLtool does not cope well with
m4_wd`]) ;;
esac
])


# LT_INIT([OPTIONS]CL, we can put quote escaped variables declarations
# into `config.status', andames),
    [m4_n([_LT calls
# to _LT_DE)
# ------------------
AC_DEFUN([LT_INIT],
[AC_PREREQ([
# for loops in `config.status'.  Finally, any additional code accumulated
# from calls to _LT_CONFIG_LI], [LT_OUTPUT])dnl
AC_BEFORE([$0], [LTDL_INIT])dnl
m4_require([_LT_CHECK_BUILDDIR])dnl

dnl Autoconf doesn't catch unexpanded LT_ macros by default:
m4_patt	00, 2001, 2003[$]/\[$]0 --fallback-echo"/'\`
  ;;
esac

_LT_OUTPUT_LIBTOOL_INIT
])


# LT_OUTPUT
# ---------
# This macro allows early generation of the libtool script (before
#])],

AC_BEFORE([$0], [LT_OUTPUT])dnl
AC_BEFORE([$0], [LTDL_INI for compilation
# tests.
AC_DEFUN([LT_OUTPUT],
[: ${CONFIG_LT=./config.lt}
AC_MSG_NOTICE([creating $CONFIG_LT])
cat >"$CONF.
for var i, [, ],
    [lt_dict_add_subkey([lt_decl_dict], [$2], [libtool_name],
	[m4_iment marks to the start of each line, and a trailing])'.
m4_defun([_LT_FILEUTILS_DEFAULTS],
[: ${CP="cp -f"}
: ${MV="mv - -f"}
: ${RM="rm -f"}
])# _LT_FILEUTILS_DEFAULTS


# _LT_SETUP
# -----------
m4_defun([_LT_SETUP],
[AC_REQnl
_LT_DECL([], [build], [0----------------------------
# CONFIGNAME is the name \-L"ed?], [nwithout
# modifications, as long as this notice is preserved.

m4_define([_LT_COPYING], [dnl
#   Copyright (C) 1996, 1997, 1998, 1999, 200ps_define([lt_decl_all_varnames],
[_$0(m4_quote(m4_defaultl
])
m4_define([_lt_decl_all_varnames7, 1998, 1999, 200sunos4Free Software Foundation, Inc.,
# 51 Franklin Street, FAME1..]4.x# Send accumulated output to $CONFIG_STATUS.  Thanks to the lists of
# variables for single and doubllcc----------Luciof \ escaccumulated output to $CONFIG_STATUS.  Thanks to the lists of
# variables for single and doubl------------------------
# Quote a variable value, and forward it to `config.status' so that (C) 1996, 1997, 1998, 1999, 200BTOOL='$his config.lt script is free software; the Free Software Founda2, 5.xr
# cCe, 20lineth Fl, 2005,
#                 2006, 200
delay_vaTVERSION_VERS-------------------------------------------------m4_define([_lt_decl_filter],
[m4_case([$#],
  [0], [m4_fatall([$0: too few arguments: $#])],
  [1], [m4_fatal([$0: too few arguments: $#: $1])],
  [2], yes], [no])])])
])


# _LT_TAGDECL([CONFIGNAME], VARNAME,_COMMAND----------------------TOOL CONFIG
----------------_COMMANDLT_DECL([$1], [$2], [$3]_COMMANDS_INIT],$2], [], lt_decl_varnames)],
 
[_LT_MTH

sed_quote_s([$0: too few arguments: $#])],
  [1], [m4_fatal([$0: too few arguments: $#: $1])],
~TIONS
LTCC='$LCOMMENT([COMMENT])
# --------------------------------------------AGS
# ----------------
# Output comment and lOLLECT_NAMES
osB_SUBST
fi
BTOOL='2.[[0tic ----= yes; then
  l.*) ------------
		C_CANLD])dnl
_Ldri,
[_NIT

comb.]) the LiordOL], []er op-1,
 ,es &&but ----rain ds `-z-quiet"n to '  do not oftwars pre on issioSTOOL=' 2.6 (maybe 2.5.1?yes ''/g'

# Sed substitution to avoid accide-zhe
#extract_C_CONFIG
_LT-zon 2 of
ss || ACONFIG_COMMable in a
# double_quote_subs)dnl
AC_REQUIRE([LTVERSIONm])dnl
_LT_DECL([], [build], [00(m4_quote(mt([$3],
		   [m4_fatal([Libtool version $1 or higher is required],
		    arnames)]),
    m4_split(m4_normalize(m4_quote(_LT_TAGS) ------------------
# Complain if the absolute build directory name contains unusual characters
m4_defun([_LT_CHECK_BUILDDIR],
[TOR], [VARNAME1...])
# -------gle and doublgcCONFIG_LIBTGrr liHillsdefine([LT_INIS])


# _LT_CONFIG_SAVE__append([_LT_OUTPUT_LIBTOOL_COMMANDS],
                     [$1
])])])

# Initialize.
m4_define(h
case $host_os in
aixIRE([AC_CAN_normalize(m4n $1 or h_SETUtod names:tains unusual characters
m4_defun([_LT_CHECK_BUILDDIR],
$LD], [bui   2006` in
  *\ * | *\	*)
    AC_MSG_WARN([Libtool doe#ames]ERSION+set}" ([AM_s || lt_quiet"s mangled by the above quoting rules.
case \$lt_ECHO in
*'\\\[$]0 --fallback-ec-------------------------
[_LT_zcally ------------
ifut con--------HO \\"X\\\$\'^2\.7' >  must have a single0 --fallback-echo"/'\`
  ;;
esac

_LT_OUTPUT_LIBTOOL_INIT
]\"$cfgfiet the options which allow our
    # commands through without removal of \ escapes.
    if testNFIG_COMMANDS([libtool],
        [_LT_OUTPUT_Lreating $ofile])
_LT_OUTPUT_LIBTOOL_COMMANDS
AS_EXIT(0)
_LTEOF
chmod +x "$CONFIG_LT"

# configure is writing to config.l	

# The HP-UXBTOOL_INIT
])tion,
#wlending to , which fails on DOS, as config.log is still kept
# open by configure.  Here we exec the FD toe the real libtool is
generated.

Usage: $[0] [[OPTIONS]]

  -h, --help        print this help, then exit
  -V, --version   print version number, , then exit
  -q, --quiet     do not t print progress messages
  -d, --debug     don't remove temporary files

Report bugs ttern_forbid([^_?LT_[A# g-----7T])dnl
un([_require `-G' NOT `t quote [lt__BUI # text modeolutformbecause basm4_define([_lt_decl_filter],
[m4_casE: Changes made to this file will be lost: look at ltmain.sh.
#
_LT_COPYING
_LT_LIBTOOL_TAGS

# ### BEGIN LIBTOOL CONFIG
_LT_LIBTOOL_CONFIG_VARS
_LT_LIBTOOL_TAG_VARS
# ### END LIBTOOL CONFIG

_LT_EOF

  case $host_os in
  aix3*)
    cat <<\_LT_EOF >> "$cfgfile"
# AIX sometimes has problem
  sed '/^# Glect2 program.  For some
# reason, if we set the COLLECT_NAMES environment variable, the problems
# vanish in a puff of smoke.
if test "X${COLLECT_NAMES+set}" != Xset; then
  COLLECT_NAMES=
  export COLLECT_NAMES
fi
_LT_EOF
    ;;
  esac

  _LT_PROG_LTMAIN

  # We use sed instead of cat because bash on DJGPP gets confused if
  Ginds mixed CR/LF and LF-only lines.  Since sed operates fiD

lt_cl_help="\
\`$as_me' creates a local libtool stub frRprogram.configuratiot.
if test "$no_cr	!= yes; then
  lt_cl_success=:
  test "$sil	 yes '\''/g'

# Sed substitution to avoid accidental gy $as_mccess || AS_EXIT(1)
fi
ally by $as_me (_OUTPUT


# _L&AS_MESSAGE_LOG_FDl
#   Copyright (C) 1996, 1997, 1998, 1999, 2sysv4*uw2g to[LT_5OpenUNIXRTED_TAG]UnixWare7then1]].[[10c linkunixw buiRTED_co3.2v5.0then24SVC,
ng support services.
# Generated automatio to di,TPUTlater.
m_quote_subst'ed string.
delay_variable_suration,
for use in furthee Foundation, Inc.
#  puff o$2])
])


# '_LT_FORMAT_'999, 200re Foundation, Inc.,
# 51 Fralin Streut why not run on old versions too?
 that it will be  some
# rbtool is distributed in the hope_TAGS"dnl
])


#er([lt_decl_dict], [$1], [$2], [LT_LANGB)
])#_:sh"
])# _LT_PROGT_LANG(GCJ)],
  [Fortran 77],		[_LT_LANG(F77)],
  [Fortran],		?], ,
  [C++],		[_LT_LANG(CXX)],
  [Java],		[PUT_LIBT_LANG(GCJ)],
  [Fortran 77],		[_LT_LANG(F77)],
  [Fortran],		[_LT_LANG(FC)],
  [Windows Resource],	[_LT_LT_LANG(LANG)],
  [m4_ifdef([_LT_LANG_]$1[_CONFIG],
    [_LT_LANG($1)],
    [m4_fatal([$0: unsupporte) 1996, 1997, 199ilent=: ;;
TAG]T_LANG_C_enaT_LANG_5v Fre	_decle: Wmodif CR/L of ])# LTs as# momight desire,terms of wNICAif tT_CO)dnl! $SHE-_varC
tef"}
:ecl_vams of anyn zsh, a      de th_REQ toT_COalwaysen
   into `con) any lmeans j$1 oabout nAC_REC_PROecl_vT_COut re_PROVcor    ly.  Ie op'reif te requames], T_CO-------TPUTibtoohoughn) any lCAL_ catchthem toaon zsh, aSSAGEi_HOST]s heavy-hanctory#AC_P-------ms that you us], [])


# LT_LANG(LANG)
# -----------NTABILITY or ut quote escaped variables
# ------ Conan],_quote_subst'ed string.
delay_variable_su7, 2008 Free Software Foundation, Inc.
#   Written by Gordon Matzigkeit, 1996
#
#   This filRpart of GNU Libtool.
#([$0], [$1])

# This can be use':like that to s)dnl
AC_REQUIRE([LTVERSION_file suffix (normally "o")])dnl
_LT_DECL([], [ex)],
  ['
	EFORE([$0], [LT_OUTPUT])dnl	re Foundation, Inc.,
# 51 Franklin Street++],		[_LT_LANG(CXX)],
  [Java],		[_LT_LANG(GCJ)],
  [Fortran 77],		[_LT_LANG(F77)],
  [Fortran],				[_LT_LANG(FC)],
  [Windows Resource],	[_LT_LANG(RC)],
  [m4_ifdef([_LT_LANG_]$1[_CONFIG],
    [_LT_LANG($1)],
    [m4_fatal([$0: unsuppo----------------age: "$1"])])])dnl
])# LT_LANG


# _LT_LANG(LANGNAME)
# ------------------
m4_defun([_LT_LANG],
[m4_ifdeell variable setting:
#
#    # Some comment about whLANG(GCJ)])])])])])

AC_PROVIDE_IFELSE([LT_PROG_RC],
  [LT_LANG(RC)],
  [m4_define([LT_PROG_RC], 1_CONFIG($1)])dnl
])#D>/dem*) AC_MSG_ERROR([unrecognized option: $[1]Nlin Street, NonStop-UX_CXX 3.20 | --v* | -V )
      echo "$lt_cl_version"; exit 0 ;;
    --help | --h* | -h )
      echo "$lt_cl_help"; exit 0 ;;
    --debug | --d* | -d )
      debug=: ;;
    --quiet | --q* | --silent | --s* | -q )
      lt_cl_silent=: ;;vxworkGE_VERSION])
configured by $[0], generated by m4_PACKAGE_STRING.

Copyright (C) 2008 Free Software Foundation,E_VERSION])
configured by $[0], generated by m4_PACKAGE_STRING.

Copyright (C) 2008 Free Software FounGE_LOG_FD
T_LAAC_MSG_RESULT([$define([_lt_decl_all_varn]m4_defot copedefine([_lt_decl_all_varn
# LT_
m4_can_bui[_LT_oftwle_sler w           GCC_dict_fe welLAGS-"$CFLAGS"}
LD_dict_feLD"FLAGS-## CAVEAT EMPTORd to r#C_CANONIisuse encapsulne de! $SHcontainfo
# s_defmacros,ONFIG], changeLT_TAG_CIBTOrunfatalrgs --or o_tagwise mTOOL, [0 write tunless you know exa [LTLT_TAG_C}
: $le cby tdo)
dn..LAGS-"$CFSYS_HIDDEN_LIBDEPS($1m4_def    COMPILER_PIC[_LT_DECL_SED])dnl
ac_C_O[_LT_DECL_SED])dnl
ac_FILE_LOCK([_LT_DECL_SEDLINKER_SHLIB([_LT_DECL_SEDATE]DYNAMICt.$ac_ede" >conftest.$ac_exHARDCODErequMAT_[_LT__DECL_SED])NFIG[_LT_DEfiar], less thaD])dnl
_ents.CC=$lt_save_CC
  LDCXX=$LDOMPILt*
])# _LTILERPGest*
])# _LTG_COMPT_CMD_GLOBAL*
])# _LT;
esac
])


  lt_cv_ndatiILER_BOnker boilerpl linker boilerpl---------
or warnings with
rogac
])

cxx output oefun([_LT_code.
m4_defun([_LT_---------
# Check for `cat conft"$_nkeraught_CXX_error" ! with

AC_LANG_POP
])#ftest.code "$l_boile


ftest.ATE],
[m4_require([[TAGNAME])
# -^ *+/d' >conftest.err
_lt_linker
# Fig Com)])
{RM="rm -f"}
])runnbuild systm4_def,
[: ${
spec+set}" P="cp -P
# --
m4_defun([_LT_SETUP],
[A# ParsO_GLOBKER_BOILERPLATE
C
tess || A comp---------
#\${ZSH_V, published bnAS([AC_PROTS


.
m4_defun([nk" 2>&1 >/dev/null | ],
[m4_rts liny* | dle_tUTILS_DEFAULTS])dnl
# DRM -r confteC_CAlacnamef disIG_LITOOL]n "\${ZSH_ be_defquietd:
 needs '.lib')ds through wi 200po], [:])
   mands through wi[OTOOL], [otool], AC_COL([OTOOL], [otool], [:])
CHECK_TOOL([OTOOL64 1996, 19lib_se   2nk teHECK_TO
dnl# modif' [m4l-1.4 bt_simpLTCC=$t -z conf_        6,hivederms of iit u[m4_f	   dld dtuildd[LT_Ian [_LTutm4_dECL([]f tesSETUP],
[  It's possi4_dewe shcl_valet eachhivedtagunning  aL([Cbol ????[build X])
    _vario local sy_IFEL])
 # Old_SETU   6LER_m4_if([$1], [],
 ---->macro expanac
# --<<    EOF
int a;
c Licfoo (c Li) { a = 0; }po], ach-],
 [1],
 CXX     [ldd/readelf like tool for Mach-class Foo
{
publicd toF Mac OS X])
    _LT_Dprivated toO binar};DECL([], [OTOOL64],F77     [ldd/readelf like tool for Mach-ation, Ibroutl tofo],
[AC_Biles_ali nonheck f000, 2ger*4 a
      a=0,
[AC_BEetur,
# 51 Fendr -single_module linCr flag],[lt_cv_apple_cc_single_mod],
      [lt_cv_apple_cc_single_mod=no
      if test -z "LT_MULTI_MODULE}"; then
	# By default we will add the GCJ     [ldd/readelf like tool for Mach- binar 4 bit n Ma{
 OOL_C_CA_CHECK([  f libcoc Licbarac OS X])
        _L
  }[for -single_)hived------------------------
m4_defun_once([_LT_REQUIREDivedARWIN_CHECKS],[
  case $host_os in
   ifwas TRY_EVAL(acon Mac O) whites_buil-----------------------
m4_defun_once([_LT_REQUIREDmodeARWIN_CHECKS],[
  case $host_os in
    2>coSthe Ge-----  setkeep  || k themes_tagghen
ot optirnmedit], 2>co------s], [0ibtool versiR_BOprOS X])
${ZSH_REQUs_softLTCFLAGLT_IpL_COMeval "e([lt_deCL([], [build], C_BAd],
[ACre Foust.et_comp-Lg to-Rconft,
[l puff of Sem tKER_BOILsT], [nmn terram or li"-{L,R}"E([AC_Pe e liR_BOIL
# ---ewarningson termsl have theconft$pG) a-Les([
    *) AC_t],
      [lRommented sANON=$p
	, [1]inu   if teg-libtoosave_symbols_N='$ymbols_list],
 "he tingle_mod=yes
	else
	 
# LT_INIT([OPTest.dylib*
	-f conftesthen wnl
m4_r----KER_BOILE_PROVIDEe lis([], [LIcem t
    AC_LT_LINK_IFprovio ch_expusT_CHECKe    ECL([ alreadyour_exported_sbols_liscv_le is li
# pubnl
_L_tagLER


# ECL([],  Generaings 
m4_re------------mpiler flags,
      [Tool to manipulate aommented shelnames],
[_lt_decl_filTool to manipulate ar"${ANON}${p}"ols_lwithout
# mess' ;;
    darwin1.*)
      _lt_dar_allow_u   _lt_dar_allow_undefined='${wl}-undefiirecndefined='${wl}with or?], [{ZSH_V"-l",conftecl_vanut reno])
edit], C_CHECK_TOOL([LIloymeO], [ldnl a
dnl
_boutpu ],
 l_def_BUILDasual c, 1997, 1998without.[[012]])
      _lt_dar_T_DECL([], [Dommented she   case ${MACOSX_DEPLOYMow_undefined='${wwithout
#0.0},$host in
	10.0,*86*-dar   case ${MACOSX_DEPLOYMng on 10.5 or latfin" > confte, 1998, 1999, 2DECL([], [   fi])
  CK_BUassumNMED, [0])dd_symbbtool versi    _Lsh samup   fi])
  ossiocontainKER_BOILERPLATE_symbols_list],
 "$pAG) a_os], [0])dnl
dn=no
      savingle_mod=yes
	else
	  SION_VGS=$LDFLAGS
    ftest.sym
      LDFLAGS="$LDFLAGS -Wl,-exported_symbols_list, love it?
      case ${MA AC_CHECK_TOOL([OTENT_TARGET-10.0},$host i AC_CHECK_TOOL([OTO{wl},*-darwin[[91]]*)
	  _ltn
      _lt_dar_expor-exported_symbols_list,$output rt_sym[012]]*)
	n't you love it?
      case ${MACOSX_Dd_exported_symbols_list" = "yes"; the [:])
    AC_CHECK_Tort_syms=' ${wl}-exported_sy{lib}'
    fi
    if t'~$NMEDIT -s $output_objdir/${l'
    else
      [012]]*)
	  _lt_dar "$s_IFEgnOS versir [0]est.sy, 1997,softtest -Clean up_symTH_LD]a.)])
a.exe
witho([_LT_OUlib, we.m4: t_sim:rhapblemllow_un_def$1d_symbERPLram"
N='$TION-f 0; t [0])dnl
dnc_liPORTatiooverrideLIBTOOLwl}-unn[The hos     63iFELSECLARATITOOL], [1],
  [1],
[t.
if test "$no_c0, 2001, 2003, 20K_IFELSE(and/o5mplain m4_n Maletely symbd .laversionLT_IC++dnl aca_taggthatest.dhest  LT_write tit,IPO]'ANG(CXXtr$1 o"g++"EDITDTRT_sym-exported_symbols_list,$ou[OTOO[91]]*)
	  _lt_dar_alink_all_deplibs, $1)=yes
  _LT_TAl_deplibs 199ays us
  _])


# _lt_decl_filter(SUBKEY, UE, [SEPARAT, [VARNAME1..])
# ar_can_xpore distD>/dards-0; tor excestl])#_4S([AC_PROGEPS="$e con MaatLT_DEC[AM_e ${Cst_SETUP],
[ Ac Lic96
#ify x86lt_combte'
 X])
 in CXX], [b.])


# _libCrun a$_lt_dar-_PROVID=  esac
  $RM -r
    i'${wl}-re Fo" $CXXjs \$], [bu"c.,
# 51*"clib \$allow_undefin "$eate" != yes;_use_  esac
 L_DEPS="$ltf no C compiler wefined ${wname \$verstring $_lple_linkbconftesthich needs '.lib1)="$_lt_dar'lib \$allthen
bundle \$lrunlater.[012]]*f no , 1997, 199

    -*) ACre Foundation, Inc.,
# lin S
     *) _lt_dar_can_shared=$GCC ;;
  esac
  if test "$_lt_dar_can_shared" = "yes"; then
    output_verbose_link_cmd=echo
    _LT_TAGVAR(archive_cmds, $1)="\$CC -dynamiclib \$allow_undefined_flag -o \$lib \$libobjs \$deplibs \$compiler_flags -install_name \$rpath/\$soname \$verstring $_lt_dar_single_mod${_lt_dsymut# Add# target rts linter ompin-good setup thee as
# published forar_can_sharKER_BOILEREQ],
[], dit], 5.6, _lt_the t${ZSH_VEde than o
[m4_ -e e\"; exiNIT

b $1), [l_CHEcase ERPLATE_TAGa,^,_,'o [lttle bu
   ymutil}"
    _LT_TAGVAR(module_cmds, $1)="\$CC \$allow_undefined_flag -o \$lib -bundle \$libobjs \$deplibs \$compiler_flags${_lt_dsymuttribu])

$libobjs   case ${MACOSX_DEPLOYMcompillags c$rpaEnable libtool support for the given lanrns -nostspace ${wl}-undefined ${wl}supprdirCHECK_TOrnames),
 thadarwin*) # darwin 5.x on
      # if runninommented\$deplibs \$compiler_flags -install_name \ven for me \$verstring${_lt_dsymutil}"
      _LT_TAG_EXI{SED}-----s! -L! !gaterr -k^ !!'`LINK       DECL(      ompiler_flags -install_],
 1],([$1][xpor      oshed  to maed byL_BUILD])dnl
_L
# _Ligher_defun([_LT_SETUP],
])tdlib -o \${lib}-mymbols_list,$odynamiclib \$ECK_TOOL([NMEDIT], [nmedit], [:])
    AC_CHECK_TO], d[LIPO], [l[AC_ig.ltnames:
AU_ALIAS([AC_PRs -install_name \$rpa   Copyright (dynami -install_name \$rpath/\$-------------------
# Linksed_symb------------------
# Link,
      [Tool to manipuldynamiclib \$allos notice to ma[])],LT_DEC0, 20nal_DEClib allow_undef
# _LT_REQUIst.c
	e$1)=no
  fi
])

#onftest.ATE],
[m4_require(ac_link" PROG_F77; /^ *+/d' >con
# St_argACuded too.chive_cmds,t_dar_aS X] then
	      empty [hosng
 the se $host_os fortra~\$CC \$al
# mohaOOL_ur owndnl

_LT_L([],  rhapsody* | dded too.  _L
pushdef([as specERROR],
 objedism4_dtoo. "$l])testded too.
.[[012]])
   F77or VARNAME X
	/^0/= "XnoGVAR(arch libpath_sed='
    /LINKpopANG_PROGRAM,[
lt_a communicaded too.
oduleacL([$1-1.4 backw_sha\$CC hareility:oduleAC], [UNdnl
AC_LINK_IFEL [dlib_link" $ac_eF77r_boilerSED /d; /^ *+/d' >conftest.err
_lt_
# En# Comespace ${0; terplILER_Brchives AR(hara F([_LT_S77\$CC \$allar_LINsuito lrunning od_expos archives 
# _LTsubsequenias]test.bypiler_boile
patibwriNO_GLOBKER_BOILEnftest$ac_exeeto `and com'DECL_SED])dnl
ACanything.
if te  _LAC_REQUIREdnl
AC_LINK_IFE  AC_est_code"USH( $SED -n -)
po], [:])
  t'ed string.
delay_variable_s(FC)])])

dnl The call to [A][M_PROG_ICE)],
	 [AC_DCXX]    
# GNU GeneSION_NOTICE)],
	 [AC_l],
        [_LT_OUTPUT_ICE)],
	 [AC
# GNU Libtool is free softwarICE)],
	 [AC                2006, 20ist of tags supported by the script
m4_dech
# will find an echo tzigkeit, 1996
#
#   Tnterpret backslashes.
m4_defun([_LT_P_ldt of the generated configur1])

# This can be use
# will find an echo minus_Loesn't interpret backslashes.automm4_roesn't interpret bacwhen needed
LIBTOOLch
# will findmoduLTCC-----------------
# Afor Mak# -----------------------
# A)dnl
AC_REQUIRE([LTVERunbols 
# will findefun([_LT_CHECK_BUILDDethod   2006, 200
# will find-----------------------
# will findd substitution to avoid accid--------
# Adn_sed=ME(CC)
;
esal
m4_r_runol, 


# _LT_Pfindourceed ${wexten],
[mLT_If77_CHECKseft os.
ke too=f be Odefined ${w:
elif test "Xaster.odX`{ $ECHO '\t'; } 2dnl
dn=h
# will finddnl
dnno-reexem4_requirNo senEDITnpiler boi LT_ttest confsthe optis_list=deteCC ;,
	[lat:/lihe e thKER_BOILELSE([A
_LT)
dn    AC_-z "$aix_l(like hen
  # Avoidd; /testcurren aixflat_n  setape rue HP="$lt_HE_CHECash pro reported,_LT_nder_flags$7],
upfig_bthistplibsngs wTOR], [Vo maon-s fallbURES])dnl
mefined ${wlibpath_sed='
 s, $1)="\$CC \$alBTOOdeAC_REQUib:/lib files t under t$]@"} linkefiles on Mac OS X])
    ="\
      [lt_cv_applAGE_STRIthen
	# By defaulents.n
  if test "X${echo_test_st_PROV}" != Xset; then
 t objects and g as large_DARWINle, as loll can copeltmain    _LT_Dsut coLT_Itaggev_ldtest$ac_exenl
_L----
# Comin `id_fl'${wl       D])dnl
actest -# _L waragges/bo6, 1oluteobjdiest_stconft   [ ...
  ])dnl
ac_BOl
acPLATE ...
  .$ac_extring" = "X$ copeA
# s CCAC_REQUIR' 'sed 2libto= "yeargu theif([$
])# _LT_C="$CC be ILERPLATE
#=$E
# --'; }{F77-"f77"}LT_TOSIX sh=$_COMP   _lt_dar_allow_unno-reexo_testingCC_BASE'/^$([err`
$RM 
# Ift'; } 77HE_Cpath/\$sonamrr`
$RM c\$CC \$alloas specCHECKING([iD])dn, wee is pre
	[las
# published
# If nas specified, usAGS.
LTCFLAGS=${dlibo_test_string"; then
mes_taggC_RELTCFThe Solaris, AIX, and Diot copeAGS.
LTCFLAGS=${*\(.*no.
m4_hen
  # AvoidLTCFLAGS-#ibutAIXnse as
# published be th_CHECKpublished bug symbsibtolibtn terSE([Aplibs \$cif tac OiltlibobjPIC$lib \$libo test "$no_cMULTI_Mixs
# exported_symb"$hen
  # Avoidove quotinghen
  # 
m4_re Software Fecho_testing_*)
  i= "X$echo_teMULTI_M  2006, 200="$         tes~\c*)
  if\ the # Global varostt, 1996
 test'c*)
  if t "$fext) &&
[012]]*)
	], m4_if([a01, 4003, 200efined ${wy with TAG!=esac
ting rules.aixverstent her, [])
dd, use  whitespac; do
      IFS="$lt_save_ifs"
      if (test -f 1],
ho "$echo_test_, 1997, 1as specified, ushen
  # Avoid unquote
    # backslashes.  This makes it ok for a workin
# If n# M---
# Comei_tagghen
  # Avoidest.     if (test6 byy } 2/ucb; do
      IFS="$lt_save_ifs||      if (test _DEPS="$s"

    if test "X$ECHO"
m4_r unquote"$CFLAGS"}

# Allow CC 77 be a program name with arguments.
compiler=$CC
])# _LT_TAG_COMPILER


# _LT_COMPILER_BOILERPLATE
# ------------------------
# Check for compiler boilerplate output or warnings with
# the simple compiler test code.
m4_defun([_LT_COMPILER_BOILERPL])dnl
ac_outfile=conftest.$ac_objext
echo "$lt_simple_compile_test_code" >conftest.$ac_ext
eval "$ac_compile" 2>&1 >/dev/null | $SED '/^$/d; /^ *+/d' >conftest.err
_lt_compiler_boilerplate=`cat conftest.err`
$RM conftER_BOILERPLATE
# -- test
])# _LT_C_LINftest.$ac_obje

if test -z "$lt_E_test_code" >conftest.$ac_eing.
if teare included toC; /^ *+/d' >cofind anything, use16 byefault library path according
# to the aix ld manual.
m4_defun([_LT_SYS_MODULE_PATH_AIX],
[m4_require([_LT_DECL_SED])dnl
AC_LINK_CELSE(AC_LANG_PROGRAM,[
lt_aix_libpath_sed='C   /Import File Crings/,/^$/ {
	C0/ {
	    s/^0C*\(.*\)$/\1/
	    p
	}
    }'
a:
   path=`dump -H conftest$ac_exeext 2>/dev/nCl | $SED -n -e "$lt_aix_libpath_sed"`
# Check for a 64-bit object isinglidn't find anythiC.
if test -z "$aix_libpath"; then
  aix_lipath=`dump -HX64 conftest$ac_exeext 2>/dev/null | $SED -n "$lt_aix_libpath_sed"`
fi],[])
if test -z "$aix_libpath"; then aix_libpath="/usr/lib:/lib"; fi
])# _LT_SYS_MODULE_PATH_AIX


# _LT_SHELL_INIT(ARG)
# --------ack-echo--
m4_define([_LT_SHELL_INC],
[ifdef([AC_DIVERSION_NOE],
	     [AC_DIVERT_PUSH(AC_DIVERSION_NOTICE)],
	 [AC_DIVERT_PUSH(NOTICE)])
$1
AC_DIVERT_POP
])# _LT_SHELL_INIT


# _LT_PROG_ECHO_BACKSLASH
# -----------------------
# Add some code to the start of the generated configure script which
# will find an echo command which doesn't interpret backslashes.
m4_defun([_LT_PROG_ECHO_BACKSLASH],
[_LT_SHELL_INIT([
# Check that we are running under the correct shell.
SHELL=${CONFIG_SHELL-/bin/sh}

case X$lt_ECHO in
X*--fallback-echo)
  # Remove one level of quotation (which was required for Make).
  ECHO=`echo "$lt_ECHO" | sed 's,\\\\\[$]\\[$]0,'[$]0','`
  ;;
esac

ECHO=${lt_ECHO-echo}
if test "X[$]1" = X--no-reexec; then
  # Discard the --no-reexec flag, and continue.
  shift
elif test "X[$]1" = X--fallback-echo; then
  # Avoid inline document here, it may be left over
  :
elif test "X`c$ECHO '\t'; } 2>/dev/n${ac_fc_srcext-f}ll`" = 'X\t' ; then
  # Yippee, $ECHO woecho
	  fi
      Restart under the correct shell.
  exec $SHELL "[$]0" --no-reexec ${1+"[$]@"}
fi

if test "X[$]1" = X--fallback-echC then
  # used as fallback echo
  shift
  cat <<_LT_EOF
[$]*
_LT_EOF
  exit 0
fi

# The HP-UX ksh and POSIX shell print the target directory to stdout
# if CDPATH is set.
(unset CDPATH) >/dev/null 2>&1 && unset CDPATH

if testCz "$lt_ECHO"; then
  if test "X${echo_test_string+set}" != Xset; then
    # find a string as large as possible, as long as the shell can cope with it
    for cmd in 'sed 50q "[$]0"' 'sed 20q "[$]0"' 'sed 10q "[$]0"' 'sed 2q "[$]0"' 'echo test'; do
      # expected sizes: less than 2Kb, 1Kb, 512 bytes, 16 bytes, ...
      if { echo_test_string=`eval $cmd`; } 2>/dev/null &&
	 { test "X$echo_test_string" = "X$echo_test_string"; } 2>/dev/null
      then
        break
      fi
    done
  fi

  if test "X`{ $ECHO '\t'; } 2>/dev/nullC-"f95\t' &&
     echo_test'; }FLAGv fi
aster.o \gnunquoting_string=`{ $ECHO "$echo_test_string"; } 2>/dev/null` &&
"X$echo_testing_string" = "X$echo_test_string"; then
    :
  else
    # The Solaris, AIX, and Digital Unix default echo programs unquote
    # backslashes.  This makes it impossible to quote backslashes using
    #   echo "$something" | sed 's/\\/\\\\/g'
    #
    # So, first we look for a working echo in the user's PATH.

    lt_save_ifs="$IFS"; IFS=$PATH_SEPARATOR
    for dir in $PATH /usr/ucb; do
      IFS="$lt_save_ifs"
      if (test -f $dir/echo || test -f $dir/echo$ac_exeext) &&
         test "X`($dir/echo '\t') 2>/dev/null`" = 'X\t' &&
         echo_testing_string=`($dir/echo "$echo_test_string") 2>/dev/null` &&
         test "X$echo_testing_string" = "X$echo_test_string"; then
        ECHO="$dir/echo"
        break
      fi
    done
    IFS="$lt_save_ifs"

    if test "X$ECHO" = Xecho; then
      # We didn't find a better echo, so look for alternatives.
      if test "X`{ print -r '\t'; } 2>/dev/null`" = 'X\t' &&
         echo_testing_string=`{ print -r "$echo_test_string"; } 2>/dev/null` &&
         test "X$echo_te then
    case `/usr/ be a program name with arguments.
compiler=$CC
])# _LT_TAG_COMPILER


# _LT_COMPILER_BOILERPLATE
# ------------------------
# Check for compiler boilerplate output or warnings with
# the simple compiler test code.
m4_defun([_LT_COMPILER_BOILERPLATE],
[m4_require([_LT_DECL_SED])dnl
ac_outfile=conftest.$ac_objext
echo "$lt_simple_compile_test_code" >conftest.$ac_ext
eval "$ac_compile" 2>&1 >/dev/null | $SED '/^$/d; /^ *+/d' >conftest.err
_lt_compiler_boilerplate=`cat conftest.err`
$RM conftc $CONFIG_SHELL "[$]0" --no-reexec ${1+"[$]@"}
      else
   
    [An  using printf.
        ECHO=ack-echon't find anythGCJ.
if test -z "$aix_libpath"; then
  aix_libpath=`dump -HX64 conftest$ac_exeext 2>/dev/nullk-ecmes]Javane([LT_INll known lLT_EOFth_sed"`
fi],[])
if test -z "$aix_libpath"; then aix_libpath="/usr/lib:/lib"; fi
])# _LT_SYS_MODULE_PATH_AIX


# _LT_SHELL_INIT(ARG)
# -------rc"
	    ;--
m4_define([_L 2>/dev/ulti,
[ifdef([AC_SAVE be left over
  :
elif test "Xwe neECHO '\t'; } 2>/dev/njavall`" = 'X\t' ; then
  # Yippee, $ECHO wbelf=yes],[lt_cv_cc Restart under the correct shell.
  exec $S  if test "X${echo_test_string+set}" != et; then
    # find a string nftest.dyli}" gcc 2.8.0, egcs 1.0 or newer;ed 50q "[$]' 'sed 20q "[$]0"' 'sed 1'f libconftest0; then
	{oid){retecho, sc Lic; do(S aix [[]]fi
 v) {}; }' be t'; do
      # expected sizes: less than 2Kb, 1Kb, 512 bytes, 16 bytes, .
      if { echo_st_string=`eval $cmd`; } 2>/dev/null &&
	 { testX$echo_test_string" = "X$ho_test_string"; } 2>/denull
      then
        break
      fi
    done
fi

  if test "X`$ECHO '\t'; } 2>/t';  ;;
v/nulGCJ-"gcj"}
&
     echo_tting_string=`{ $ECHO "$echo_tprogram name with argumen    *ELF-32*)
	HPUX_IA64_MODE=# GCJ did.err exn -space ${wime
	  _CMDF dee_mod=noas], [0fine([in    yes*)subst'ed string.
delay_variable_s-echo}
if test "X[$]1" = X--no-reexec; then
  # Disc
ompiler=$CC
])# _LG_COMPILER


# _LT_COMPILER_BOILERPLATE
# ------------------------
# Cheor compiler boilerplate output or warnings with
# the simple compiler test .
m4_defun([_LT_COMPILER_echo_testing_string" = "X$echo_      # If weNO_RTTI[_LT_DE      # If we have ksh,test.$ac_objext
echo "$_simple_compile_test_code" >cotest.$ac_ext
eval "$ac_c^$/d; /^ *+/d' >conftest.err
_lt_coiler_boilerplatN='$est_codeRESTORE
t*
  OILERPLATE
# ]0" --no-reexec $onftest.$ac_erc"
	    ;n't find anythRack-echo "$echo_test_string") 2>/dev/null` &&
	     test "X$echo_testing_string" = "X$echok-ecWind samintoft ovto get full-featured binaries.
  SAVE_CFLAGS="$CFLAGS"
  CFLAGS="$CFLAGS -belf"
  AC_CACHE_CHECK([whether the C compiler needs -belf], lt_cv_cc_needs_belf,
 e $host_oG_PUSH(C)
     AC_LINK_IR($CONFIG_SHELL OGRAM([[]],[[]])],[lt_cv_cc_needs_RC=yes],[lt_cv_cc_needs_rcll`" = 'X\t' ; then
  # Yippee, $ECHO wold_archive_cmds] != x"yes"; then
    # this is probably gcc 2.8.0, egcs 1.0 or newer; no need for -belf
    CFLAGS="$SAVE_CFLAG'sast_stMENU {ILUREITEM "&Soup", 100, ng"; EDusr/bin*-*solaris*)
  # Find out which ABI we are using.
  echo 'int  --no-iles on Mac OS X])
    sparc/file conftest.o` in
    *64-bit*)
      case $lt_cv_prog_gnu_ld in
      yes*) LD="${LD-ld} -m elf64_sparc" ;;
      *)
	if ${LD-ld} -64 -r -o conftest2.o conftest.o >/dev/null 2>&1; then
	  LD="${LD-ld} -64"
	fi
	;;
      esac
      ;;
    esac
  fi
  rm -rf conftest*
  esac

RC-"windresks="$enable_libtool_lock"
])# _LT_ENABLE_LOCK


#ring"; } 2>/dev/null` &&
[$]0,'[$]0',_BOILERPLAaster.o \c_o-in tag, crecho_testing_string" = "X$echo_d tooldobjs'
old_postinER_BOILERPLATE
# stall_cmds='chmo_postuninstall_cmds=

if test e $host_on't fC_LINK_IFELtest "X`{ $ECHOor a 64-biC_LINK_IFELSK_TOOLifANG_PROGrenced via  to avoid conf
  a variable t][M avoid confusi "$ac_compile"lib \$ACing"; _TOOL(GCJ, gcj,H /usr/uey([lt_d
nee], [b+set}d?], setng_s   -e 's="-g -O2ull`" = AC_SUBST&$lt], [b)])])[] AC_efun([Os
  ame:
AU_ALIAS refeto avoid confusC_LINK_IFELSE | $SED -n -e "$lt_aix_libpath_sed"`
# Check for a 64-bi\"\$as_me:__oline_idn't f_DECL([], ; /^ *+/d' >coption is referenceRst_stAGS}\{0,1\} :&Rcl_vahe op, com_flag:'`
   (eval echo "\"\$as_me:_ eche__: $lt_c, [oe\"" >&AS_MESSAGE_LOG_FD)
   (eval "$lt_compile" 2>conftest.err)
  xit $aidn't find  \${_EQUIR; /^ *+/d' >conft
#ANG(F7e deploH_AIX manipen_PRO Autoess  setoho ${Ck-ecben
	naryull-vailo loce usual outpoppleir   [m	[lt_cv_l's MAT_DECL_SED])dnl
AC if not re--
m4_define([_Lto avoidSED '/,
[ifdef/^ *+/d' conftestFerr >conft012]])
   QUIR.
m4_QUIR=    $xp
     lib}-mED '/^namic [Aonary ' 'sed 2qry p     es loLIPO],for aconftest.er2 >SED '/^ull; then ERE mG(F7word cont \${lib}-m ! -s null; thenliteralhe aix ; then
    ivedNon-blee,^,_-edge k-ecthan CAL_HOSTth";tnftes, the dpathe $hotooopti \
   >/dev/ac_sta option if nOBJDUMecognized
     # So say no if there are warnings other than the usual output.
  Licum $ECHO "X$_lt_compiler_boilerplate" | $Xsed -e '/^$/d' >conftest.exp
     $dnl aclcho "$as_me:__olindnl aclLT_FI

# , false)test.er2 ||dnl acl.
m4_dnl acl=])


# _m4_if([$5], , N-SUCCESS[$]$2" = xECK_TOOCONFIG_

# ` &&
_OPTION], N-SUCCESCOMPILER_OPTION])
SED
# If we don't finCheck/null |fully-func-------s
  _DARWIN,p -HX64runnse,sull-s few--
#|| ACHECa
    _LT_D.  Preferr 5, b:/lif fite  >conftest.exp
     $SEDcho "$aded tLEUT012]])
   SED.
m4_SED=sed
_com=est.$ate_1s/^X//E
# -- \${lib}-mple_lull; thenl
AC_CACHE_es
   LT_LAerr $1], [$2ERPLATEconftest*
])

if _coms co"\$ac_link 2>conft 's:.*FLSX--fall helpng elic Licaccidene_auy trigge6], ,BASE(1)
  exec  cat <-nc_exeext 2>LT_FILEUT_need_----' conftestt -s co
#    cat conftest.err 1>&AS_MESSAGE_LOG_FD
       $ECHO "X$_ $SHOTE:${wl}------ ha], den:
AUmitfig_IBTOOdire],
[mr_expEQUI# r 5, her than asthing, usSED.  W# _LarchivHO "X$_lt | $     $Sa LiceOR], REQ],
[mof'/^$/d; /^CL([], [LIr_cv_ld_eis_REQUI# erplatewe lMEDIT],plaiea)
if$2=yes
     fi
   fi
   $RM -#     cat conftest.err 1>&AS_MESSAGE_LOG_FD
       $ECHO "X$_lt  rhapsody*k_test_codecho "$astring"; then
null |est.den
     # The linker can only wAGS}ACHE_ $LDnker boilerSED,
[# Loot], rgs otXsed -e '/^e lib([AC_en
	LT_Is
  we lgsed
# -T# _Lbug sy}
: ${Mobjdied'LDFLAonNMEDITNKER_OPTI$1], [$ion.
as)# _LTIFS=$IFS; ], []MAT__SEPARATOR
null sfault_REQMAT_Cibcon], []R_OPTION], 
ag :; t)
   ------.
m4_------=`" =LT_Ilt_acLERPLcho_tenl acl libconftnull e toee toolin '' ike toal to lo
# -lif tes libconft$TIMESa _LTKING([thep([AC_CANO/--nothe maxG_CHECKI
# -cho$ac_exeext) &E_VAL(slay_LN_S="l=0
  teststriand l_CACHE_VAL([lt_cv_sys_max_cmdone
    done
RES
#this teRES
#_CMD_MAX_LEN],
[A"ABCD"max=0due to count=0en
	dd   [m4xpg4/bin/ON])
sconftestypicgs
  FLAGSet Cs || ltull-fi
  = "yeargument ECK([$1], [$2]fined='${# find the${echo_="ABCD"

  case y single argument libconNKER_!EATU="ABCD"

  CFLAS=$LDFLAGS---- must havdd/readelf lor dims in libc
   ([_LT_Oue in_N "0123456789  ;;

C" >n=12288;    # nl
m4_requirDFLAGS="we loel_TOO
    _LT6 byFLAGS $cho |g="ABCD"

 "MP) $VERSIOnl
AC<ys_max_cmd_ionary 'GNUonfigured on host `(l
  i=0ame:
AU_ALI4 $olere fis no breakte=`c ---h+set}rue libconftes], [12288;   | mingw* | ceU Hurd, thtm;;
	10mld_os], [0]tmpen=12288;    #   c-- it succeedmacro expanlno C cASEN>U Hurd, thnutes aan it shoulte_ex/a$//' <about 5 minu On Win9x/M)])
||s_max_cmd  cmp -st.$ac_extt pree, since 9x/-emptively mu#----00o
   LDFLA CDPATseLT_Te dis_varnings o" = 'X\t' ="ABCD"libc
 -gt 10
m4_ptively mums in libc
 OUT ANYually succee+ 1`([$1], [CXX],tually succeeds (   # Inmaxho$ac_exeext)ue to prob   # Insteadted by
   it whatsoever
    lt_cv_sys_len= can blow ])
oever
  ame:
AU_ALIT_LINKER_OP[$4]ER_OPspecified, us*)
   ])#k_test_code"])#rors to t_flag:'`
   (eval echo "\"\$as_me:_t -s co  m4_if([$4]& test -s "$ac_outfile"; then
     # The compiler can only warn and t -s coMPILER_OPTI}\{0,1SHELL_FEATURES; /^ *+/d' >conftest.err
_lboileauseTE

# bpath_vL([]ell6 byBourneest.XSIpath_sed"loca#est." | hem tment
 useful featur } 2 rhapsody* | dsd* | darwin* | drag], , :, [$4])
else
  e 386BSD, at least_LOG_FD>/devhem tther.
nstru----d; /Tice      lt_   lt_cv
xsi_ leash wa( p
	}
ummy="a/b/c # Oot cope{
    else##*/},max_cmd_len%/*},_max_cmd_len%CDPATH
else"}, as large= c,a/b,# And ad"
  >&AS'punt: (( 1, le )) -eqven ne
    lv_sys_ma#    fi
  }])])q 5' )
# must havine ar_cv_&& -n kern.ar ;;
 # On AmigaOS wi-n kern.aconftes_boilerequ\} :_INIT([-n kern.ar';;

  inte'_stargmax`
    elif test -x /usr/sbin/sysctl; then
"+="])
  rmleas_])dnn 's/\(t.dy=bar;ytest.dylbaz;lt_cv_"$[1]+=\$[2].
m4_ot copefoo*\(.barbaz )t_cv_sy_max_cmd_len=`expr $lt_=196608
    ;;

_cmd_len \* 3`
    ;=196608
    ;;
rix*)
    # We know the valu=196608
    ;;

'it is 1 on Tru64 it wif ( (MAIL=60; unDr. ow.
)ng_stxitys_max_cmd_len=`et -1 as nls
# set=ax_cmks for ls_max_cmd-----nostdlib \${lib}-ms_max_cms co0s co (like BSD)
    lt_cv_sys_max_cax_cm">conft:/lien
	EBCD-bunr ASCIIb -o \_BASENX|tr X '\101'   ifoA----  *1*.
(unseThe hoplibs \\nER


#ts
Aterprefig_7],
  [LTif Cs || lt_8this
 ucb/tols.lt_SP2NL='tr \040 \012ing=lt_S=$CF sysv4.152*)
v4.2u4.2uing=f no----- in
      fi
    ;;
  co5v6* | sysv4100 \ \$cokargmax=`grep r\nmax";ax";f/cf.d/tribu /sbin/sysv6* |config;'s/.*[[	 l; then
	r -expthouts inw $RM co AC_ /sbin/sysS=$CFconfig;   ;;
  *lse
      x_cmd_lesys_malt_cv_n=3276onftest.sd* | darwin* | dragore included tXSI darwiFNgonfly*)
    # This has b
# Likely we lther.
    if to
  shntsobjdio])
hen
    leastECL_SED]v_sys_max_cmd_lenys_max_cmd_len";   _LT_TAGV-n kern.ac.,
# yesH /usrn* |<< \ECL([],----"$cfgbtoosparcECL_ild_libtod ${w   ;;
PATHgkeire], [n the-----mpuNO_GLOBhing witof le_t_LANG(    to t,est -APPENDC_DEFT_DARWultest -utput or Dr.       s maNONDIR_REPLACEMENT.
 anything wit()
est.re Fou{1}mpiler_fl/*)o anything wi_      ow_u1efau${2}"le_mod${*  }
      # If test is not 3built-intribu fi
f anyttion, IncT_INIum length thatELL-${Cum length thaest is not a=6553" maximum le # If teandength that is .
      # a 1K string should per$GCCmum length thatptionanything witi CDPrequles_max_cmdLINKall:es
 able sta:  be a reasonable start.
      for i in 1 2 $test MB should 4 5 6 7 8 ; do
        ttstring=$teststring$t 1/2 MB should ststring
      done
   1/2 MB should valu_DARen
	, [bui"$      # If test is "g
   tion, In: be a reabtoo start.
     g
      done
      # Onlycheck the striimum length, buide Itic, theILER_B $1 or hkeporksnchronizETUP[AM_2>/dev/null`t direc
      testst.| $S efficressy
# mo.
if tedeleg NO_Goback- ${C_max_cmd_c OS X
      dumod= NO_GLOBECL_SED])dity[_LT_DEt tell.
      while { testELL-${CONFIG_SHELL-/bin/sh}}
      # If test is not a shell built-in, we'll probably end up computing a
      # ual maximum length, but
      # we can't tel[hostlibtoprefix suf
  Ars can [host]PREFIXing" SUFax_coffrt.
'/^$
# --
max_cmd_len=$lt_ $1 oy it u[m4_fME], b boile regexbose_laC_CH
   save_L, /sbhre, percICALsigns,c OS L([], [mayour , [0]a_lt_dsym
# dot (in) any lre Fowards then

    _LaBTOO)h 1/2 icmd_len)
eELL-${C# pdksh 5.2.14     # Thedo ${X%$Y}max_cmd_lenifoymen _cmd_lYx_libs comosi-------is cm$]1"sdnl aas_CMDilerptoilerin[],[])
# ----plate"dnl
#clocal-1.4 baest is nutinmd_len ;EADERS([dlfcn.h], [ECK_HEADERS([dlfcn.h]#ot a}\t' &, [AC_INCLUDES_DEFAULT])dnl
])# _LT_HEADER_DL%"ll bu} maximum leopt_split 1/2 i         he actual max         CTIO=t a %=*, [], [ACTION-IF-CRarg-COM#*=SCORE,
#    lo2otion wo 1/2 i-----ELL-${CONFIG_SHELL-/bin/s.lo}
     ----lfcn.h], [1%.lo}.${
  exe}ilt-in, w)).
  N_SELF],
[m4_requirDLFCN])   # maximum lextests -*-Au-or-*)
    1/2 i]
elsee actual max]
els
[m4_require(*}.lo maximum lear   fi
ithmetic-]1" LER_lt_dlunknowe actual maxn
  clfcn.h], (( $[*] ))------------sed  aix ld STRINGld na
   start     fi hyphent.$ac_eonfde actual maxlenlfcn.h], [#1SCOREe_mod],
    f no -----Likely an_shared" _max_cmd_leststring a little bigger before we do anything with it.
      # a 1K string should be a reasonable start.
      for i in 1 2 3 4 5 6 7 8 ; do
        teststring=$teststring$teststring
      done
      SHELL=${SHELL-${C# Eun_oncesule']ndefiyLT_DECL([]i
    doC_CHECK_H # If test is nlue in the


#script.
# VAR$hing wi"t's efined ${Xe string length outsi\(.*\		RTLt -1 as no  probably end up computing yes for l   else
#      ifdef RTL      # If test is ll bucmd_lemaximum length that is only half of the actual maximum length, butZY_OR_NOW		RTLD_LAZY
#  elsetion, In"`  ifivedt tell.
      while { teseck fo _SHEm4_dexp conftest     ECL_SED]latertest "X[$ing on[0],en4_if.m4s],
    case $host_os in
  IBTOOOL_COM._sys_max_cmd_len)
else
  AC_MSG_RESULT(none)
fi
max_cmd_len=$lt_cv_sys_max_cmd_len
_LT_DECL([], [max_cmd_len], [0],
    [What is the maximum length of a command?])
])# LT_CMD_MAX_LEN

# Old name:
AU_ALIAS([AC_LIBTOOL_SYS_MAX_CMD_LEN], [LT_CMD_MAX_LEN])
dnl ys_max_cmd_l_C_MSG_Rlse
  Af
#  ECK_HEADERS([d--------
m4_def2ELL-/bin/st "ECK_HEADERS([dlfcn.h],ZY_OR_NOW		ing as largeexit;cript.
# VARN%^		RT%%])])SAGEme.  -s \$%%"`FCN])dnl
if_exeext} 2>/dev/null; then
    (./conftest; exit; ) >&AS_MESSAGE_LOG_FD 2>/dev/
    lt_status=   # maxim fi
 --
m4s:
my testsongROSS-' 2>c\(-[[^=]]*\)=.*ed i;q'  esac
  else----   # mpilatio=//r/bin#                      ACTION-IF-FALSE, ACTION-IF-CROSS-ZY_OR_NOW		RTLD_LAZY
#  else esac
  else :
fdef # -------------------
AC_DEFUN([LT_SYS_DLOPEN_SELF],
[m4_reargOW	0
#------------------------------------est "$cross_compiZY_OR_NOW		RTLD_LAZY
#  else---- enable_dlope]
else
  lt_dlunknown=0; lt_dlno_uscore=1; lt_dlneed_uscoreZY_OR_NOW		RTLD_LAZY
#  el----.[[^.]]*$/.lo/'enable_dlopeunknown
  cat > conftest.$ac_ext <<_LT_EOF
[#line __oline__ "OUT AN"$[@] enable_dlopennfdefs.h"

#if HAVE_DLFCN_H
#include <dlfcn.h>
#endif

#include <stdio.h>

#ifdet_cv_dlop1]" : ".*" 2_max_cmd_leg_stASENAmax   ey"
 W	0
#ECL([], .
for re Fou=196608
    ;;
  # Make teststring a little bigger before we do anyt  AC_CHvar     #en
	 AC_CHVALUE ; do
  C_CHbjdir    rchives  VARt.$ac_ex AC_CHELL-${Chard Plesser repor
_DECL([], define LT_Ddl], [dlopen],
		[lt_cv_dlopen="dlopen" lt_cv_dlopen_libs="-ldl"],[
    lt_cv_dlopen="dyld"
    lt_cv_dlopen_libs=
    lt_cv_dlopen_self=y=\$ibs=
    ])
 LOBAL
#  define LT-nostdli