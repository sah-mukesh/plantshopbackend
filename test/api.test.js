const request = require("supertest");
const app = require("../index");
 
describe("API Testings", () => {
  //individual test cases
  //testing the test route '/test'
  it("GET /test | Response with valid text Hello", async () => {
    const response = await request(app).get("/test");
    expect(response.statusCode).toBe(200);
    expect(response.text).toBe("Hello from express server");
  });
 
  //testing get all products route || 'api/product/get_products'
  it("GET /api/product/get_products | Response with valid json", async () => {
    const response = await request(app).get("/api/product/get_products");
    expect(response.statusCode).toBe(200);
    expect(response.body).toBeDefined();
    expect(response.body.success).toBe(true);
    expect(response.body.message).toBe("Products fetched successfully");
  });
 
  //testing user resgistration route '/api/user/create'
  it("POST /api/user/create | Response with valid json", async () => {
    const response = await request(app).post("/api/user/create").send({
      firstName: "test",
      lastName: "test",
      email: "test123@gmail.com",
      password: "test123",
    });
    console.log(response.body);
    if (response.body.success) {
      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe("User created successfully");
    } else {
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe("User already exists.");
    }
  });
 
  //write test for login route
  //it will pass when user is registered
  it("POST /api/user/login |Response with valid json", async () => {
    const response = await request(app).post("/api/user/login").send({
      email: "test123@gmail.com",
      password: "test123",
    });
    expect(response.body.success).toBe(true);
    expect(response.body.message).toBe("User logged in successfully.");
 
    //token exists or not
    expect(response.body.token).toBeDefined();
  });
 
  it("GET Product | Fetch single product", async () => {
    const response = await request(app).get(
      "/api/product/get_product/6581002f1ba6ba64edda399a"
    );
    expect(response.statusCode).toBe(200);
    expect(response.body).toHaveProperty("product");
  });
});
 