include config.mk

generate_lib: $(TARGET).a
	ar -t $(TARGET).a


all: $(TARGET).a
	$(MAKE) -C . -f $(MAKE_NAME) examples

TESTS = code code1  

# Regla principal que genera todos los tests
examples: generate_lib $(addprefix $(PATH_EXAMPLES)/, $(addsuffix .$(EXTENSION), $(TESTS)))
	@echo "generando tests... $^"

# Regla patrón: compila cada test a partir de su fuente .c
$(PATH_EXAMPLES)/%.$(EXTENSION): $(PATH_EXAMPLES)/%.c
	$(CC) $< $(CFLAGS_EXAMPLES) -o $@ 


$(TARGET).a: $(OBJECTS)
	$(ARR) $(ARR_FLAGS) $@ $^
	ranlib $@

$(TARGET)_debug.a: $(addsuffix .o, $(OBJECTS))
	$(ARR) $(ARR_FLAGS) $(TARGET).a $^
	ranlib $(TARGET).a

gen_obj: $(addsuffix .o, $(OBJECTS))
	@echo "generando archivos objeto... $^"


# Regla general: compilar cada .c en su correspondiente .o
%.o: %.c
	@echo "Compilando $< ..."
	$(CC) $(CFLAGS) -c $< -o $@

cleanobj:
	@echo "Eliminando todos los archivos .o..."
ifeq ($(OS),Windows_NT)
	@for /R %%i in (*.o) do $(RM) $(RMFLAGS) "%%i"
else
	@find . -type f -name "*.o" -delete
endif
	

cleanall: cleanobj
	@$(RM) $(RMFLAGS) $(TARGET).a
ifeq ($(OS),Windows_NT)
	@$(RM) $(RMFLAGS) $(PATH_EXAMPLES)\*.$(EXTENSION)
else
	@$(RM)  $(RMFLAGS) $(PATH_EXAMPLES)/*.$(EXTENSION)
endif
	

.SILENT: clean cleanobj cleanall
.IGNORE: cleanobj cleanall
.PHONY:  cleanobj cleanall