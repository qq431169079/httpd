mod_flashapp.la: mod_flashapp.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_flashapp.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_flashapp.la
