'''
Created on 5 nov. 2018

@author: pgg
https://wiki.python.org/moin/ConfigParserExamples

Lector del fichero de configuracion conf/conf.ini. Es una capa fina por
encima del modulo estandar configparser: lee el .ini una sola vez y ofrece
metodos comodos para sacar valores como booleano, entero o como diccionario.
'''
import configparser


class ConfigReader(object):
    '''
    classdocs
    '''

    config = None

    def __init__(self, config_file):
        '''
        Constructor
        '''
        # Cargamos el fichero .ini en memoria al crear el objeto.
        print('  -> Cargando la configuracion desde ' + config_file)
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        # Mostramos por consola que secciones se han encontrado ([App], etc.).
        print('  -> Secciones cargadas:')
        print('    => ' + str(self.config.sections()))
        print('-----------------------------------------------------------------')

    def getBoolean(self, section, option):
        # Devuelve la opcion interpretada como booleano (true/false, 1/0...).
        return self.config.getboolean(section, option)

    def getInt(self, section, option):
        # Devuelve la opcion interpretada como entero.
        return self.config.getint(section, option)

    def ConfigSectionMap(self, section):
        # Devuelve TODA una seccion del .ini como un diccionario
        # {opcion: valor}. Si una opcion falla, la deja a None.
        dict1 = {}
        options = self.config.options(section)
        for option in options:
            try:
                dict1[option] = self.config.get(section, option)
                if dict1[option] == -1:
                    print("skip: %s" % option)
            except:
                print("exception on %s!" % option)
                dict1[option] = None
        return dict1
