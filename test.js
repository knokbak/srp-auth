const { ClientSetup, Algorithm, Groups, ClientAuthenticate } = require('./dist');

(async () => {

    const setup = new ClientSetup({
        username: 'hello',
        password: 'world',
        group: Groups.b1024,
        algorithm: Algorithm.SHA_256,
    });
    
    await setup.init().then(console.log).catch(console.error);
    
    const authenticate = new ClientAuthenticate({
        username: 'hello',
        password: 'world',
        group: Groups.b1024,
        algorithm: Algorithm.SHA_256,
    });
    
    await authenticate.init().then(console.log).catch(console.error);
    await authenticate.exchange('abcdef', setup.s).then(console.log).catch(console.error);
    await authenticate.authenticate().then(console.log).catch(console.error);

})();
