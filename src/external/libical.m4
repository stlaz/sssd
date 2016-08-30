AC_SUBST(ICAL_CFLAGS)
AC_SUBST(ICAL_LIBS)

PKG_CHECK_MODULES(ICAL, ical >= 1.0.0, [found_libical=yes],[found_libical=no])
AS_IF([test x"found_libical" != xyes],
    [AC_CHECK_HEADER([libical/ical.h],
        [AC_CHECK_LIB([ical],
                      [icalparser_new],
                      [ICAL_LIBS="-lical"],
                      [AC_MSG_ERROR([libical is missing icalparser_new])],
                      [-lical])],
        [AC_MSG_ERROR([libical header files are not installed])])]
)
