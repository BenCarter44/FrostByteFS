echo "Comprehensive File System Test ###############################"

echo -e "\nDirectories #####################################################\n"
mkdir testA
ls
cd testA
echo -e "\nFiles #####################################################\n"
echo "Hello" > test.txt
cd ../
cat testA/test.txt
rm testA/test.txt
touch fileA.txt
echo "Text" >> fileA.txt
ls -l
cat fileA.txt
rm -rf testA/

# Scale
echo -e "\nScale Test #####################################################\n"
mkdir scale
cd scale
mkdir files
cd files
for i in {1..20000}; do touch "file_$i"; done
# Count
find . -maxdepth 1 -type f | wc -l
cd ../
mkdir directories
cd directories
for i in {1..20000}; do mkdir "dir_$i"; done
find . -maxdepth 1 -type d | wc -l
cd ../
mkdir remove
cd remove
for i in {1..20000}; do touch "rm_$i"; done
cd ../
rm -rf remove/
ls

cd ../

echo -e "\n Copy on Write Test #####################################################\n"

dd if=/dev/zero of=zerosfile bs=128 count=3200 conv=notrunc
ls -lh
du -h zerosfile

dd if=/dev/urandom of=randfile bs=128 count=3200
ls -lh | grep randfile
du -h randfile

# Advanced 
echo -e "\n Concurrency #####################################################\n"
for i in {1..5000}; do echo A >> concur_log; done &
for i in {1..5000}; do echo B >> concur_log; done &

echo -e "\n Timestamp #####################################################\n"
touch x
stat x
sleep 1
echo data >> x
stat x

echo -e "\n Links #####################################################\n"
echo "data" > file
ln file hard
ln -s file sym
ls -lai
rm hard
ls -lai
rm file
ls -lai
rm sym
ls -lai

# Permissions
echo -e "\n Permissions #####################################################\n"
touch testperm.txt
ls -l
chown ubuntu testperm.txt
chgrp ubuntu testperm.txt
chmod g+rw testperm.txt

echo -e "\n Extended File Attr #####################################################\n"
touch testex.txt
setfattr -n user.desc -v "hello" testex.txt
getfattr -d testex.txt

echo -e "\n Sparse Files #####################################################\n"
truncate -s 1G sparse.img
du -h sparse.img   # physical disk usage (small)
ls -lh sparse.img  # logical size (large)


# Advanced
echo -e "\n Real World Test #####################################################\n"

echo -e "\n Git & Compile #####################################################\n"
git clone https://github.com/sqlite/sqlite.git

cd sqlite
git fetch --all --tags
git checkout -b test tags/version-3.51.0
cd ../
mkdir sqlitebuild
cd sqlitebuild
../sqlite/configure
make sqlite3

echo -e "\n unzip & sqlite ###################################################\n"

wget https://codingcando.com/skillscope/skillscope_data.zip
unzip skillscope_data.zip
rm skillscope_data.zip
sha1sum skillscope_data.db
echo "Correct: 9ba1b3200a5830e039158264126b20d1152e4d43  skillscope_data.db"
echo -e "\n"
date
touch out.csv
./sqlite3 skillscope_data.db "SELECT * FROM vw_nlbse_tool_competition_data_by_issue;" -csv > out.csv &
while true; do
    count=$(wc -l < out.csv)
    printf "\rLines: %s of 7154" "$count"
    sleep 0.05
    if [ "$count" -ge "7153" ]; then
        break
    fi
done
date
echo -e "\n"
cd ../

echo -e "\n TAR ###################################################\n"

# Download TAR of many files
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.17.8.tar.xz
sha1sum linux-6.17.8.tar.xz
tar -xf linux-6.17.8.tar.xz
tar -cf archive.tar linux-6.17.8
du -h archive.tar   # physical disk usage (small)
ls -lh archive.tar  # logical size (large)

# Pip
echo -e "\n PIP ###################################################\n"

python3 -m virtualenv venv
source venv/bin/activate
pip install tensorflow
python3 -c "import tensorflow"
deactivate
