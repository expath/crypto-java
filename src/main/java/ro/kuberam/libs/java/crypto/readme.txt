For installing the cryptographic XQuery extension module for eXist, please follow the steps below.

1. Drop x-krypt.jar into $EXIST_HOME/lib/extensions.
2. Add <module class="ro.kuberam.xcrypt.XcryptModule" uri="http://kuberam.ro/ns/x-crypt" /> to builtin-modules in conf.xml.
3. For examples of usage, see the tests, located in tests folder (the project's archive includes also
the keystore needed; just drop it in eXist, in root collection). The tests can be ran by using
kert, the testing automation (http://sourceforge.net/projects/kert).