FROM centos:6
ARG GITBRANCH
ENV GITBRANCH {$GITBRANCH:-master}
ENV LD_LIBRARY_PATH /usr/lib
RUN yum -y install gcc openssl-devel bzip2-devel
RUN yum -y install git wget  
RUN cd /usr/src && wget https://www.python.org/ftp/python/2.7.16/Python-2.7.16.tgz
RUN cd /usr/src && tar -xvf Python-2.7.16.tgz
RUN cd /usr/src/Python-2.7.16 && ./configure --prefix=/usr/local/python2.7 --enable-optimizations --enable-shared && make install altinstall
RUN ln -s /usr/local/python2.7/lib/libpython2.7.so /usr/lib
RUN ln -s /usr/local/python2.7/lib/libpython2.7.so.1.0 /usr/lib
RUN ln -s /usr/local/python2.7/bin/python2.7 /usr/local/bin
RUN /sbin/ldconfig -v 
RUN curl "https://bootstrap.pypa.io/get-pip.py" -o "get-pip.py" && python2.7 get-pip.py
ENV PATH $PATH:/usr/local/python2.7:/usr/local/python2.7/bin 
RUN cd /root/ &&  git clone https://github.com/carbonblack/cb-threatconnect-connector
WORKDIR /root/cb-threatconnect-connector
RUN git checkout $GITBRRANCH
RUN pip2.7 install -r requirements.txt
RUN mkdir -p /root/rpmbuild/SOURCES
RUN yum -y install rpm-build
RUN python2.7 setup.py bdist_binaryrpm
CMD ["/bin/bash","-c"]

