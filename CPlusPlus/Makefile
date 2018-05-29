#
#
BINDIR = ./bin

LIB = smtpclient
EXES = mail_tester

RM :=rm -f 

CXXFLAGS = -g -Wall -I./src
CPPFLAGS = -g -Wall -I./src
LIBS =-lssl -l${LIB}

LIB_NAME=$(BINDIR)/lib$(LIB).a
LIB_OBJS = ./src/smtp_client.o 

all: lib test

dir:
	if [ ! -d $(BINDIR) ]; then mkdir $(BINDIR) ; fi;

lib:  dir $(LIB)
	
$(LIB): $(LIB_OBJS)
	ar -cr $(LIB_NAME)  $^

test: dir  $(LIB_NAME)  
	g++ $(CXXFLAGS) $(CPPFLAGS) -o $(BINDIR)/$(EXES)  test/main.cpp -L$(BINDIR) $(LIBS) 
	
clean:
	$(RM) $(LIB_OBJS)
	$(RM) $(BINDIR)/*
#
#
