describe("Web app", () => {
  it("Successfully loads", () => {
    cy.visit("/");
  });

  it("Custom icon per query is displayed", () => {
    cy.visit("/");

    cy.get('[data-testid="BiotechIcon"]').should("exist");
    cy.get('[data-testid="BrushIcon"]').should("exist");
  })

  it("Fetch status source info on query failed", () => {
    cy.visit("/");

    cy.contains("My favourite musicians").click();
    cy.contains("Finished in:");
    cy.get('[aria-label="Sources info"]').click();

    cy.get('[aria-label="Query failed"]').should("exist");
  });

  it("Fetch status source info on query success", () => {
    cy.visit("/");

    cy.contains("My wish list").click();
    cy.contains("Finished in:");
    cy.get('[aria-label="Sources info"]').click();

    cy.get('[aria-label="Query was succesful"]').should("exist");
  });

  it("Authentication needed source info for query on public data", () => {
    cy.visit("/");

    cy.contains("My wish list").click();
    cy.contains("Finished in:");
    cy.get('[aria-label="Sources info"]').click();

    cy.get('[aria-label="No authentication required"]').should("exist");
  });

  it("Authentication needed source info for query on private data", () => {
    cy.visit("/");

    cy.get('[aria-label="Profile"]').click();
    cy.contains('[role="menuitem"]', "Login").click();

    cy.get('input[name="idp"]').clear();
    cy.get('input[name="idp"]').type("http://localhost:8080");
    cy.contains("Login").click();

    cy.get("input#email").type("hello@example.com");
    cy.get("input#password").type("abc123");
    cy.contains("button", "Log in").click();
    cy.contains("button", "Authorize").click();

    cy.url().should("eq", "http://localhost:5173/");

    cy.contains("A list of my favorite books").click();
    cy.contains("Finished in:");
    cy.get('[aria-label="Sources info"]').click();

    cy.get('[aria-label="Authentication required"]').should("exist");
  });

  it("Authentication needed source info for query on failing query", () => {
    cy.visit("/");

    cy.contains("My favourite musicians").click();
    cy.contains("Finished in:");
    cy.get('[aria-label="Sources info"]').click();

    cy.get('[aria-label="Uncertain if authentication is required"]').should(
      "exist"
    );
  });

  it("Variables in column header contain link to ontology", () => {
    cy.visit("/");

    cy.contains("My favourite musicians").click();
    cy.contains("Finished in:");
    cy.get('a[href="http://schema.org/name"]');
  })

  it("When one source throws an error, the results of other sources are still shown", () => {
    cy.visit("/");

    cy.contains("My favourite musicians").click();
    cy.contains("Finished in:");
    cy.contains("Ludwig van Beethoven");
  });

  it("Log in with WebID with no OIDC issuer", () => {
    cy.visit("/");

    cy.get('[aria-label="Profile"]').click();
    cy.contains('[role="menuitem"]', "Login").click();

    cy.get('input[value="webId"]').click();

    cy.get('input[name="idp"]')
      .clear();
    cy.get('input[name="idp"]')
      .type("http://localhost:8080/example2/profile/card#me");
    cy.contains("Login").click();

    cy.contains("No IDP found");
  });

  it("Log in with invalid WebID document", () => {
    cy.visit("/");

    cy.get('[aria-label="Profile"]').click();
    cy.contains('[role="menuitem"]', "Login").click();

    cy.get('input[value="webId"]').click();

    cy.get('input[name="idp"]')
      .clear();
    cy.get('input[name="idp"]')
      .type("http://localhost:8080/invalidWebId/profile/card#me");
    cy.contains("Login").click();

    cy.contains("Couldn't query the Identity Provider from the WebID");
  });

  it("Log in with an invalid IDP issuer", () => {
    cy.visit("/");

    cy.get('[aria-label="Profile"]').click();
    cy.contains('[role="menuitem"]', "Login").click();

    cy.get('input[name="idp"]')
      .clear();
    cy.get('input[name="idp"]')
      .type("https://facebook.com");
    cy.contains("Login").click();

    cy.contains("Login failed");
  });

  it("Log in and execute query on private data", () => {
    cy.visit("/");

    cy.get('[aria-label="Profile"]').click();
    cy.contains('[role="menuitem"]', "Login").click();

    cy.get('input[name="idp"]').clear();
    cy.get('input[name="idp"]').type("http://localhost:8080");
    cy.contains("Login").click();

    cy.get("input#email").type("hello@example.com");
    cy.get("input#password").type("abc123");
    cy.contains("button", "Log in").click();
    cy.contains("button", "Authorize").click();

    cy.url().should("eq", "http://localhost:5173/");

    cy.contains("A list of my favorite books").click();
    cy.contains("It Ends With Us");
  });

  it("Query on private data unauthenticated", () => {
    cy.visit("/");

    cy.contains("A list of my favorite books").click();
    cy.get("div").should("have.class", "MuiSnackbarContent-message");
  });

  it('Querying resource with "bad" cors header, though a proxy should work', () => {
    cy.visit("/");

    cy.contains("My idols").click();
    cy.get(".MuiSnackbarContent-message").should("not.exist");
  });

  it("Query public data", () => {
    cy.visit("/");

    cy.contains("My wish list").click();
    cy.contains("Too Late");
  });

  it("Querying variable ending on _img should return an image as result", () => {
    cy.visit("/");

    cy.contains("A Test For Images").click();
    cy.contains("Finished in:");
    cy.get("td").find("img");
  });
});
