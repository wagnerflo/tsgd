#!/usr/bin/env python3

if __name__ == '__main__':
    import asyncio
    import logging
    import ssl

    from aiohttp import web
    from .rdg import RemoteDesktopGateway

    # configure logging
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger('tsgd')

    # get loop
    loop = asyncio.get_event_loop()

    # create ssl context
    sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sslctx.load_cert_chain('cert.crt', 'cert.key')
    # sslctx.set_ciphers(':'.join([
    #     'GOST2012256-GOST89-GOST89', 'GOST2001-GOST89-GOST89',
    #     'AES256-GCM-SHA384', 'AES256-SHA256', 'AES256-SHA',
    #     'CAMELLIA256-SHA256', 'CAMELLIA256-SHA',
    #     'AES128-GCM-SHA256', 'AES128-SHA256', 'AES128-SHA',
    #     'CAMELLIA128-SHA256', 'CAMELLIA128-SHA'
    # ]))

    # defaults
    host = '0.0.0.0'
    port = 8443

    async def main():
        app = RemoteDesktopGateway()
        server = web.Server(app.handler)
        runner = web.ServerRunner(server)
        await runner.setup()
        site = web.TCPSite(
            runner, host=host, port=port, ssl_context=sslctx)
        await site.start()
        logger.info('Serving on https://{}:{}/'.format(host, port))
        while True:
            await asyncio.sleep(3600)

    try:
        main_task = loop.create_task(main())
        loop.run_until_complete(main_task)
    except (web.GracefulExit, KeyboardInterrupt):
        pass
    finally:
        web._cancel_tasks({main_task}, loop)
        web._cancel_tasks(web.all_tasks(loop), loop)
        loop.close()
