const { ClientSetup, Algorithm, Groups, ClientAuthenticate } = require('./dist');

(async () => {

    const start = Date.now();
    let counter = 0;
    while (Date.now() - start < 1000) {
        const setup = new ClientSetup({
            username: 'hello',
            password: 'world',
            group: Groups.b4096,
            algorithm: Algorithm.SHA3_512,
        });
        
        await setup.init().then(console.log).catch(console.error);
        counter++
    }
    console.log(counter);
    
    /*const authenticate = new ClientAuthenticate({
        username: 'hello',
        password: 'world',
        group: Groups.b8192,
        algorithm: Algorithm.SHA3_512,
    });
    
    await authenticate.init().then(console.log).catch(console.error);
    await authenticate.exchange('abcdef', setup.s).then(console.log).catch(console.error);
    await authenticate.authenticate().then(console.log).catch(console.error);*/

})();
