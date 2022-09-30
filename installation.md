
### Essential Step (before installing):
### sudo apt-get update && sudo apt-get install -y git build-essential cmake wget curl
### Remember to sudo all commands

1. Go to home directory and make a directory called "tools" to store all the folders:

cd $home && mkdir tools && cd tools

2. Copy all folders into the "tools" directory:

git clone https://github.com/stp/minisat && \
git clone https://github.com/msoos/cryptominisat && \
git clone https://github.com/stp/stp && \
git clone https://github.com/kste/cryptosmt

3. Go into the "minisat" directory and install minisat along with all required packages:

cd $home && cd tools && cd minisat
sudo apt-get install -y zlib1g-dev
sudo make && sudo make install

4. Go back to "tools" directory, go into the "cryptominisat" directory and install cryptominisat (CMS) along with all required packages:

cd $home && cd tools && cd cryptominisat
sudo apt-get install -y libm4ri-dev python3 python3-dev libboost-all-dev
mkdir build
cd build
sudo cmake ../ && sudo make && sudo make install

5. Go back to "tools" directory, go into the "stp" directory and install STP along with all required packages:

cd $home && cd tools && cd stp
sudo apt-get install -y bison flex
mkdir build
cd build
sudo cmake ../ && sudo make && sudo make install

6. Go back to "tools" directory, go into the "cryptosmt" directory and install necessary packages:

cd $home && cd tools && cd cryptosmt
sudo apt-get install -y python3-pip
sudo pip3 install pyyaml

7. Clean workspace
sudo apt-get clean && sudo rm -rf /var/lib/apt/lists/*
