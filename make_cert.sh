#!/bin/sh
cfile=cert.h
crt=s.crt
key=s.key
if [ -e $cfile -o -e $crt -o -e $key ]; then
    echo "Files exist. Not overwriting."
    exit 1
fi
openssl req -x509 -new -keyout $key -out $crt -nodes
echo 'static char s_crt[] = "\' > $cfile
sed 's/$/\\n\\/' $crt >> $cfile
echo -e '";\n' >> $cfile
echo 'static char s_key[] = "\' >> $cfile
sed 's/$/\\n\\/' $key >> $cfile
echo -e '";' >> $cfile
rm "$crt" "$key"
