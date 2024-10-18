import asyncio
from sys import exit

HOST = "127.0.0.1"
PORT = 4000

async def connect_tcp():
    try:
        reader, writer = await asyncio.open_connection(HOST, PORT)
    except:
        print("Couldn't connect to server.")
        exit(1)

    try:
        while True:
            message = input("Enter string to send to server(exit to terminate): ")
            if message.lower() == 'exit':
                break
            
            writer.write((message + '\n').encode())
            await writer.drain()

            data = await reader.readline()
            print(f"Received: {data.decode().strip()}")

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        print("Closing the connection.")
        writer.close()
        await writer.wait_closed()

if __name__ == "__main__":
    try:
        asyncio.run(connect_tcp())
    except KeyboardInterrupt:
        print("Keyboard interrupt detected. Terminating.\n")