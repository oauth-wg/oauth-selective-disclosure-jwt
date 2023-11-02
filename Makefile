LIBDIR := lib
include $(LIBDIR)/main.mk

$(LIBDIR)/main.mk:
ifneq (,$(shell grep "path *= *$(LIBDIR)" .gitmodules 2>/dev/null))
	git submodule sync
	git submodule update $(CLONE_ARGS) --init
else
	git clone -q --depth 10 $(CLONE_ARGS) \
	    -b main https://github.com/martinthomson/i-d-template $(LIBDIR)
	(cd $(LIBDIR) && git checkout 3e5cfbafc0037fee41e7fe4e6567b14b3c1be199) # Temporarily pin to a specific commit right before it upgraded mmark from 2.2.10 to 2.2.40 as the latter is producing XML from the current markdown that xml2rfc rejects
endif
