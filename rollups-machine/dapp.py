from os import environ
import os
import subprocess
import logging
import requests

logging.basicConfig(level="INFO")
logger = logging.getLogger(__name__)

rollup_server = environ["ROLLUP_HTTP_SERVER_URL"]
logger.info(f"HTTP rollup_server url is {rollup_server}")
lambada_server = environ["LAMBADA_HTTP_SERVER_URL"]

logger.info(f"Lambada server is {lambada_server}")

def verify_log(cartridge_path: str, log: bytes,riv_args: str = None,in_card: bytes = None, entropy: str = None,
               frame: int =None,get_outhist=False,get_screenshot=False) -> dict[str,bytes]:
    log_path = "/run/replaylog"
    outcard_path = "/run/outcard"
    incard_path = "/run/incard"
    screenshot_path = "/run/screenshot"

    with open(log_path,'wb') as log_file:
        log_file.write(log)

    if os.path.exists(outcard_path): os.remove(outcard_path)
    if os.path.exists(screenshot_path): os.remove(screenshot_path)

    if in_card is not None and len(in_card) > 0:
        incard_file = open(incard_path,'wb')
        incard_file.write(in_card)
        incard_file.close()

    run_args = []
    run_args.append("/rivos/usr/sbin/riv-chroot")
    run_args.append("/rivos")
    run_args.extend(["--setenv", "RIV_CARTRIDGE", cartridge_path])
    run_args.extend(["--setenv", "RIV_REPLAYLOG", log_path])
    run_args.extend(["--setenv", "RIV_OUTCARD", outcard_path])
    if get_screenshot:
        run_args.extend(["--setenv", "RIV_SAVE_SCREENSHOT", screenshot_path])
    else:
        run_args.extend(["--setenv", "RIV_NO_YIELD", "y"])
        
    if in_card is not None and len(in_card) > 0:
        run_args.extend(["--setenv", "RIV_INCARD", incard_path])
    if frame is not None:
        run_args.extend(["--setenv", "RIV_STOP_FRAME", f"{frame}"])
    if entropy is not None:
        run_args.extend(["--setenv", "RIV_ENTROPY", f"{entropy}"])
    run_args.append("riv-run")
    if riv_args is not None and len(riv_args) > 0:
        run_args.extend(riv_args.split())
    result = subprocess.run(run_args)
    if result.returncode != 0:
        os.remove(log_path)
        raise Exception(f"Error processing log: {str(result.stderr)}")

    with open(outcard_path,'rb') as f:
        outcard_raw = f.read()
    os.remove(outcard_path)

    screenshot = b''
    if os.path.exists(screenshot_path):
        with open(screenshot_path,'rb') as f: screenshot = f.read()
        print(f"screenshot was read, length {len(screenshot)}")
        os.remove(screenshot_path)

    os.remove(log_path)

    return {"screenshot":screenshot, "outcard":outcard_raw}

def handle_advance(data):
    logger.info(f"Received advance request data {data}")
    try:
        log = bytearray.fromhex(data["payload"][2:])
        res = verify_log("/cartridges/freedoom.sqfs", log, get_screenshot = True)
        outcard = res["outcard"]
        print("== Outcard ==")
        print(outcard.decode('ascii'))
        print("State opened successfully.")
        screenshot = res["screenshot"]
        print(f"Length of screenshot: {len(screenshot)}")
        try: 
            response = requests.get(lambada_server + "/open_state")
            response.raise_for_status() 
        except requests.exceptions.HTTPError as errh: 
            return "reject"

        try: 
            response = requests.post(lambada_server + "/set_state/outcard", data = outcard, headers={'Content-Type': 'application/octet-stream'})
            response.raise_for_status() 
        except requests.exceptions.HTTPError as errh: 
            return "reject"

        try: 
            response = requests.post(lambada_server + "/set_state/screenshot.png", data = res["screenshot"], headers={'Content-Type': 'application/octet-stream'})
            response.raise_for_status() 
        except requests.exceptions.HTTPError as errh:
            print("Something went wrong storing the screenshot")
            return "reject"

        print("State set successfully.")

        try: 
            response = requests.get(lambada_server + "/commit_state")
            response.raise_for_status() 
        except requests.exceptions.HTTPError as errh: 
            return "reject"

        print("State committed successfully.")
                
        return "accept"
    except Exception as e:
        print(f"something went wrong {e}")
        # something is happening weirdly in lambada here
        return "reject"

def handle_inspect(data):
    logger.info(f"Received inspect request data {data}")
    return "accept"

handlers = {
    "advance_state": handle_advance,
    "inspect_state": handle_inspect,
}

finish = {"status": "accept"}

while True:
    logger.info("Sending finish")
    response = requests.post(rollup_server + "/finish", json=finish)
    logger.info(f"Received finish status {response.status_code}")
    if response.status_code == 202:
        logger.info("No pending rollup request, trying again")
    else:
        rollup_request = response.json()
        data = rollup_request["data"]
        handler = handlers[rollup_request["request_type"]]
        finish["status"] = handler(rollup_request["data"])
