import asyncio

HOST = "127.0.0.1"
PORT = 4000

async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    print(f"New connection from {addr}")

    try:
        while True:
            data = await asyncio.wait_for(reader.readline(), timeout=30.0)

            if not data:
                break

            message = data.decode().strip()
            print(f"Received '{message}' from {addr}")

            writer.write(data)
            await writer.drain()
            print(f"Sent: '{message}' to {addr}")

    except asyncio.TimeoutError:
        print(f"Connection to {addr} timed out. Closing connection.")

    except Exception as e:
        print(f"An error occurred with connection '{addr}': {e}")

    finally:
        print(f"Closing connection to {addr}")
        writer.close() 
        await writer.wait_closed()

async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Keyboard interrupt detected. Terminating.\n")