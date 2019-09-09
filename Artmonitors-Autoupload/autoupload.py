import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

import base64
import requests
import sys
import json
from pprint import pprint
from PIL import Image, ImageTk
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.config(bg="gray50")
        self.pack(expand=True, fill="both")
        self.works = []
        self.work_frames = []
        self.work_view = 0
        self.base_url = "http://artmonitors.com/add_collection"  # "http://localhost/add_collection"
        self.create_widgets()

    def create_widgets(self):
        root.geometry("1000x900")

        # create options for initializing collection
        self.url_frame = tk.LabelFrame(master=self, text="HTTP POST url")
        self.url_frame.pack(side="top", expand=True, fill="x")

        self.url_textbox = tk.Text(master=self.url_frame, height=1)
        self.url_textbox.pack(expand=True, fill="x")
        self.url_textbox.insert(tk.END, self.base_url)

        self.top_frame = tk.LabelFrame(master=self)
        self.top_frame.pack(side="top", expand=True, fill="x")

        self.top_top_subframe = tk.Frame(master=self.top_frame)
        self.top_top_subframe.pack(side="top", expand=True, fill="x")

        self.top_scroll_buttons_subframe = tk.Frame(master=self.top_frame)
        self.top_scroll_buttons_subframe.pack(side="bottom", expand=True, fill="x")

        self.top_bottom_subframe = tk.Frame(master=self.top_frame)
        self.top_bottom_subframe.pack(side="bottom", expand=True, fill="x")

        self.top_middle_subframe = tk.LabelFrame(master=self.top_frame, text="Description")
        self.top_middle_subframe.pack(side="bottom", expand=True, fill="x")

        self.collection_name_labelframe = tk.LabelFrame(master=self.top_frame, text="Collection Name")
        self.collection_name_labelframe.pack(side="right", expand=True, fill="x")

        self.collection_name_textbox = tk.Text(master=self.collection_name_labelframe, height=1, width=40)
        self.collection_name_textbox.pack(expand=True, fill="x")

        self.collection_abbrev_labelframe = tk.LabelFrame(master=self.top_frame, text="Abbreviation")
        self.collection_abbrev_labelframe.pack(side="left", expand=False, fill="none")

        self.collection_abbrev_textbox = tk.Text(master=self.collection_abbrev_labelframe, height=1, width=10)
        self.collection_abbrev_textbox.pack()

        self.collection_description_label = tk.Label(master=self.top_middle_subframe,
                                                     text="(Collection: {{collection:oma:Some Text}}           "
                                                          "Local Work: {{work:deep-pond:Some Text}}           "
                                                          "Other Work: {{other:oma:deep-pond:Some Text}})")
        self.collection_description_label.pack(side="top", expand=True, fill="x")

        self.collection_description_textarea = tk.Text(master=self.top_middle_subframe, height=15)
        self.collection_description_textarea.pack(side="bottom", expand=True, fill="both")

        self.upload_file_button = tk.Button(master=self.top_bottom_subframe, text="Import Works...", command=self.upload_files_dialog)
        self.upload_file_button.pack(side="left", expand=True, fill="x")

        self.submit_button = tk.Button(master=self, text="Submit Collection", command=self.submit_collection)
        self.submit_button.pack(side="bottom", expand=True, fill="x")

        self.bottom_frame = tk.LabelFrame(master=self, bg="gray70")
        self.bottom_frame.pack(side="bottom", expand=True, fill="both")

        self.bottom_scroll_back_button = tk.Button(master=self.top_scroll_buttons_subframe, text="<", command=self.scroll_back)
        self.bottom_scroll_back_button.pack(side="left", expand=True, fill="both")

        self.bottom_scroll_forward_button = tk.Button(master=self.top_scroll_buttons_subframe, text=">", command=self.scroll_forward)
        self.bottom_scroll_forward_button.pack(side="right", expand=True, fill="both")

    def upload_files_dialog(self):
        filenames = filedialog.askopenfilenames(title="Choose Works to Upload")
        self.gather_works(filenames)
        self.show_works()

    def gather_works(self, filenames=[]):
        # gather filenames
        for f in filenames:
            w = self.Work(path=f)
            if w not in self.works:
                self.works.append(w)
            else:
                idx = self.works.index(w)
                self.works[idx].name = w.name
                self.works[idx].filename = w.filename
        # remake widgets
        for work in self.works:
            work_frame = tk.LabelFrame(master=self.bottom_frame)

            work_img = tk.Label(master=work_frame, image=work.tkimage)
            work_img.pack(side="left", expand=False)

            inner_frame = tk.Frame(master=work_frame)
            inner_frame.pack(side="right", expand=True, fill="both")

            work_name_frame = tk.LabelFrame(master=inner_frame, text="Name")
            work_name_frame.pack(side="top", expand=True, fill="x")

            work_name_textbox = tk.Text(master=work_name_frame, height=1)
            work_name_textbox.insert(tk.END, work.name)
            work.tkname = work_name_textbox
            work_name_textbox.pack(expand=True, fill="both")

            work_filename_frame = tk.LabelFrame(master=inner_frame, text="Filename")
            work_filename_frame.pack(side="top", expand=True, fill="x")

            work_filename_textbox = tk.Text(master=work_filename_frame, height=1)
            work_filename_textbox.insert(tk.END, work.filename)
            work.tkfilename = work_filename_textbox
            work_filename_textbox.pack(side="top", expand=True, fill="both")

            work_description_frame = tk.LabelFrame(master=inner_frame, text="Description")
            work_description_frame.pack(side="top", expand=True, fill="both")

            work_description_textbox = tk.Text(master=work_description_frame, height=3)
            work_description_textbox.insert(tk.END, work.description)
            work.tkdescription = work_description_textbox
            work_description_textbox.pack(side="bottom", expand=True, fill="both")

            work.tkframe = work_frame

        print(self.bottom_frame.winfo_children())

    def show_works(self):
        for w in self.works:
            w.tkframe.pack_forget()
        top_work = self.works[self.work_view]
        bottom_work = self.works[self.work_view + 1] if self.work_view + 1 < len(self.works) else None

        top_work.tkframe.pack(side="top", expand=True, fill="x")
        if bottom_work:
            bottom_work.tkframe.pack(side="bottom", expand=True, fill="x")

    def scroll_forward(self):
        if self.work_view + 2 < len(self.works):
            self.work_view += 2
        self.show_works()

    def scroll_back(self):
        if self.work_view - 2 >= 0:
            self.work_view -= 2
        self.show_works()

    def submit_collection(self):
        def decrypt_message(encoded_encrypted_msg, private_key):
            # source: https://gist.github.com/syedrakib/241b68f5aeaefd7ef8e2
            # decrypted = decryptor.decrypt(ast.literal_eval(str(encrypted)))
            decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
            decryptor = PKCS1_OAEP.new(private_key)
            decoded_decrypted_msg = decryptor.decrypt(decoded_encrypted_msg)
            # decoded_decrypted_msg = private_key.decrypt(decoded_encrypted_msg)
            return decoded_decrypted_msg

        def encrypt_message(a_message, public_key):
            # source: https://gist.github.com/syedrakib/241b68f5aeaefd7ef8e2
            encryptor = PKCS1_OAEP.new(public_key)
            encrypted_msg = encryptor.encrypt(a_message)
            # encrypted_msg = public_key.encrypt(a_message, 32)[0]
            encoded_encrypted_msg = base64.b64encode(encrypted_msg)  # base64 encoded strings are database friendly
            return encoded_encrypted_msg

        # retrieve and encode key
        with open('keys/random_key', 'rb') as random_key_file:
            random_string = random_key_file.read()
        with open('keys/add_collection_rsa_key.pub', 'rb') as rsa_key_file:
            public_key = RSA.importKey(rsa_key_file.read())
        key = encrypt_message(random_string, public_key)

        # assign collection values
        collection_name = self.collection_name_textbox.get("1.0", "end-1c")
        collection_abbrev = self.collection_abbrev_textbox.get("1.0", "end-1c")
        collection_description = self.collection_description_textarea.get("1.0", "end-1c")

        data = {
            "key": key.decode('utf8'),
            "name": collection_name,
            "abbrev": collection_abbrev,
            "description": collection_description,
            "works": []
        }

        # compile each work's entry in data
        for work in self.works:
            work_name = work.tkname.get("1.0", "end-1c")
            work_filename = work.tkfilename.get("1.0", "end-1c")
            work_desc = work.tkdescription.get("1.0", "end-1c")
            with open(work.path, 'rb') as work_file:
                work_imgdata = base64.encodebytes(work_file.read())
            entry = {
                "name": work_name,
                "filename": work_filename,
                "description": work_desc if len(work_desc) > 0 else None,
                "img": work_imgdata.decode('utf8')
            }
            data["works"].append(entry)

        # prepare request
        url = self.url_textbox.get("1.0", "end-1c")
        with open('keys/add_collection_permissions', 'r') as auth_file:
            auth_components = auth_file.read().split('\n')
            auth = (auth_components[0], auth_components[1])

        # send request
        print("Sending request to url %s" % url)
        headers = {
            'content-type': 'application/json'
        }
        response = requests.post(url=url, data=json.dumps(data), headers=headers, auth=auth)

        if response.status_code != 200:
            print("Upload Failed: Error %s" % response.status_code)
            print(response.json()['stacktrace'])
            messagebox.showerror("Upload Failed: Error %s" % response.status_code,
                                 response.json()['stacktrace'])
            return

        print("Got response: %s" % str(response))
        resp_json = response.json()

        with open('keys/add_collection_client_key', 'rb') as private_key_file:
            private_key = RSA.importKey(private_key_file.read())
        new_key = decrypt_message(resp_json['key'], private_key)
        with open('keys/random_key', 'wb') as new_key_file:
            new_key_file.write(new_key)

        messagebox.showinfo("Upload Succeeded", "Upload of collection was successful")

    class Work:
        def __init__(self, path):
            self.path = path
            self.filename = path[path.rindex('/') + 1:]
            self.name = self.filename[:self.filename.rindex('.')]
            self.image = Image.open(self.path)
            self.image.thumbnail((256, 256), Image.ANTIALIAS)
            self.description = ""
            self.tkframe = None

            self.tkname = None
            self.tkfilename = None
            self.tkdescription = None
            self.tkimage = ImageTk.PhotoImage(self.image)

        def __eq__(self, other):
            return self.path == other.path


if __name__ == "__main__":
    root = tk.Tk()
    root.title("Add Collection")
    app = Application(master=root)
    app.mainloop()