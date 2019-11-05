CC = gcc
FLAGS = -Wall
TARGET = libcaronte.a
LIBS = -lrt -lcrypto


SRC = \
	utils.c \
	base64.c \
	cJSON.c \
	hashmap.c \
	http_client.c \
	caronte_security.c \
	caronte_client.c

OBJS := ${SRC:.c=.o}


all:
	$(CC) $(FLAGS) -c $(SRC) $(LIBS)
	ar rc $(TARGET) $(OBJS)
	ranlib $(TARGET)

sample:
	$(CC) $(FLAGS) -o client_sample sample.c $(SRC) $(LIBS)

clean:
	rm -rf $(TARGET) $(OBJS) client_sample
