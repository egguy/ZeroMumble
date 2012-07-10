
class MumbleService(object):
    def __init__(self, secret):
        import Ice, IcePy
        
        # Setup Ice
        icepath = Ice.getSliceDir()

        prop = Ice.createProperties([])
        prop.setProperty("Ice.ImplicitContext", "Shared")
        prop.setProperty("Ice.MessageSizeMax",  "65535")
       
        idd = Ice.InitializationData()
        idd.properties = prop

        ice = Ice.initialize(idd)
        
        # Set the secret
        ice.getImplicitContext().put( "secret", secret )
        
        # Initialization of a local connexion
        prx = ice.stringToProxy('Meta:tcp -h localhost -p 6502')
        prx.ice_ping()

        # Load the object definition
        Ice.loadSlice( '', ['-I' + icepath, "Murmur.ice" ] )

        import Murmur
        self._murmur     = Murmur.MetaPrx.checkedCast(prx)
        
        # Generic ACL ready to use
        self._password_ACL = [
            Murmur.ACL(
                applyHere = True,
                applySubs = False,
                inherited = False,
                userid = -1,
                group = "all",
                allow = 0,
                deny = 910,
            ), Murmur.ACL(
                applyHere = True,
                applySubs = False,
                inherited = False,
                userid = -1,
                # The password is defined by adding a # in front of group name
                group = "",
                allow = 910,
                deny = 0,
            )
        ]

        self._server = self._murmur.getServer(1)

    def create_channel(self, name):
        """Create a channel
        
        args:
            name (str): The name of the channel
        return:
            A channel id
        """
        cid = self._server.addChannel(name, 0)
        return cid
        
        
    def set_password(self, channel_id, password):
        """Set the password for a channel_id
        
        args:
            channel_id (int): the channel identifier
            password (str): The password in cleartext
        """ 
        raw_acls, raw_groups, raw_inherit = self._server.getACL(channel_id)
        self._password_ACL[1].group = "#%s" % password
        self._server.setACL(channel_id, raw_acls+self._password_ACL, raw_groups, raw_inherit)
        
    def create_passworded_channel(self, name, password):
        "Create and set password"
        channel_id = self.create_channel(name)
        self.set_password(channel_id, password)
        
    def list_channels(self):
        """Return the list of channels
        
        return:
            A list of channel information
        """
        chan_info = self._server.getChannels().values()
        return [{ "name": x.name, "id": x.id, "parent": x.parent } for x in chan_info]


if __name__ == "__main__":
    import sys
    import zerorpc

    s = zerorpc.Server(MumbleService(sys.argv[1]))
    s.bind("tcp://0.0.0.0:1234")
    s.run()
        


