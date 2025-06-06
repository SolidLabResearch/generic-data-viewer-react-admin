import { orderedUrl } from "../support/utils";

describe("Custom Query Editor tests", () => {
  it("Create a new simple query", () => {
    cy.visit("/#/customQuery");

    cy.get('input[name="name"]').type("new simple query");
    cy.get('textarea[name="description"]').type("new description");
    cy.get('input[name="source"]').type("http://localhost:8080/example/wish-list");

    cy.setCodeMirrorValue("#sparql-edit-field-queryString", "This is not a valid SPARQL query");

    cy.contains("Invalid SPARQL query.");
    cy.get('button[type="submit"]').click();
    cy.contains("Invalid SPARQL query.");

    // This incomplete SPARQL query passes the SPARQL edit field syntax checker, but will fail when executed
    cy.setCodeMirrorValue("#sparql-edit-field-queryString", "SELECT")

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    cy.contains("Something went wrong").should('exist');

    cy.get('button').contains("Edit Query").click();

    cy.setCodeMirrorValue("#sparql-edit-field-queryString", `PREFIX schema: <http://schema.org/>

      SELECT * WHERE {
          ?list schema:name ?listTitle;
            schema:itemListElement [
            schema:name ?bookTitle;
            schema:creator [
              schema:name ?authorName
            ]
          ].
      }`);

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    // Checking if the book query works
    cy.contains("Colleen Hoover").should('exist');

    // Check if updating the custom query results in changed results - here we just change a column name
    cy.get('button').contains("Edit Query").click();

    cy.setCodeMirrorValue("#sparql-edit-field-queryString", `PREFIX schema: <http://schema.org/>

      SELECT * WHERE {
          ?list schema:name ?listTitle;
            schema:itemListElement [
            schema:name ?bookTitleColumnNameChangedXXX;
            schema:creator [
              schema:name ?authorName
            ]
          ].
      }`);

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    cy.contains("bookTitleColumnNameChangedXXX").should('exist');
  });

  it("Create a new simple query with a Comunica context", () => {
    cy.visit("/#/customQuery");

    cy.get('input[name="name"]').type("new simple query with comunica context");
    cy.get('textarea[name="description"]').type("new description");

    cy.setCodeMirrorValue("#sparql-edit-field-queryString", `PREFIX schema: <http://schema.org/> 

      SELECT * WHERE {
          ?list schema:name ?listTitle;
            schema:itemListElement [
            schema:name ?bookTitle;
            schema:creator [
              schema:name ?authorName
            ]
          ].
      }`);

    cy.get('input[name="source"]').type("http://localhost:8080/example/wish-list ; http://huppledepup.doesnotexist.com/we-want-lenient");

    cy.get('input[name="comunicaContextCheck"]').click();

    cy.setCodeMirrorValue("#json-edit-field-comunicaContext", `{"lenient": truezzz}`);

    cy.contains("Invalid Comunica context configuration.");
    cy.get('input[name="comunicaContextCheck"]').click();
    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('input[name="comunicaContextCheck"]').click();
    cy.get('button[type="submit"]').click();
    cy.contains("Invalid Comunica context configuration.");

    cy.setCodeMirrorValue("#json-edit-field-comunicaContext", `{"lenient": true}`);

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    // Checking if the book query works
    cy.contains("Colleen Hoover").should('exist');

    // Check if updating the custom query results in changed results - here we just undo the Comunica context, resulting in Comunica failing to fetch
    cy.get('button').contains("Edit Query").click();

    cy.get('input[name="comunicaContextCheck"]').click();

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    cy.contains("Something went wrong").should('exist');
  });

  it("Create a new query, with multiple sources", () => {
    cy.visit("/#/customQuery");

    cy.get('input[name="name"]').type("material query");
    cy.get('textarea[name="description"]').type("this query has 3 sources");

    cy.setCodeMirrorValue("#sparql-edit-field-queryString", `# Query Texon's components
# Datasources: https://css5.onto-deside.ilabt.imec.be/texon/data/dt/out/components.ttl

PREFIX oo: <http://purl.org/openorg/>
PREFIX ao: <http://purl.org/ontology/ao/core#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX d: <https://www.example.com/data/>
PREFIX o: <https://www.example.com/ont/>

SELECT DISTINCT ?component ?componentName ?recycledContentPercentage
WHERE {
	?component
		a o:Component ;
		o:name ?componentName ;
	  o:recycled-content-percentage ?recycledContentPercentage ;
		.
}
ORDER BY ?componentName
`);

    cy.get('input[name="source"]').type("http://localhost:8080/verifiable-example/components-vc ; http://localhost:8080/verifiable-example/components-vc-incorrect-proof ; http://localhost:8080/example/components");

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    // Checking if the query works
    cy.contains("https://www.example.com/data/component-c01").should('exist');

    // Check if updating the custom query results in changed results - here we just add something to the last source, making it a not existing source, resulting in Comunica failing to fetch
    cy.get('button').contains("Edit Query").click();

    cy.get('input[name="source"]').type("hihihahahoho");

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    cy.contains("Something went wrong").should('exist');
  });

  it("Create a new query, here an ASK query", () => {
    cy.visit("/#/customQuery");

    cy.get('input[name="name"]').type("Is there an artist etc...");
    cy.get('textarea[name="description"]').type("Test an ASK query");

    cy.setCodeMirrorValue("#sparql-edit-field-queryString", `PREFIX foaf: <http://xmlns.com/foaf/0.1/>
PREFIX dbo: <http://dbpedia.org/ontology/>
PREFIX dbp: <http://dbpedia.org/resource/>
ASK WHERE {
  ?person a dbo:Artist.
  ?person foaf:name ?name.
  ?person dbo:influencedBy dbp:Pablo_Picasso.
}`);

    cy.get('input[name="source"]').type("http://localhost:8080/example/artists");

    cy.get('input[name="askQueryCheck"]').click()

    cy.setCodeMirrorValue("#json-edit-field-askQuery", '"trueText":"Yes, there is at least one artist influenced by Picasso!","falseText":"No, there is not a single artist influenced by Picasso."}')

    cy.contains("Invalid ASK query specification.");
    cy.get('input[name="askQueryCheck"]').click()
    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('input[name="askQueryCheck"]').click()
    cy.get('button[type="submit"]').click();
    cy.contains("Invalid ASK query specification.");

    cy.setCodeMirrorValue("#json-edit-field-askQuery", '{"trueText":"Yes, there is at least one artist influenced by Picasso!","falseText":"No, there is not a single artist influenced by Picasso."}')

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    // Check if the query works
    cy.contains("Yes, there is at least one artist influenced by Picasso!")

    // Check if updating the custom query results in changed results - here we just change the askQuery details
    cy.get('button').contains("Edit Query").click();

    cy.setCodeMirrorValue("#json-edit-field-askQuery", '{"trueText":"Yezzzzz","falseText":"Noooooooooo"}')

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    cy.contains("Yezzzzz")
  });

  it("Create a new query, here with http proxies", () => {
    cy.visit("/#/customQuery");

    cy.get('input[name="name"]').type("My idols custom...");
    cy.get('textarea[name="description"]').type("Test a query with http proxies");

    cy.setCodeMirrorValue("#sparql-edit-field-queryString", `PREFIX schema: <http://schema.org/> 
SELECT ?name ?birthDate_int WHERE {
    ?list schema:name ?listTitle;
      schema:itemListElement [
      schema:name ?name;
      schema:birthDate ?birthDate_int;
    ].
}`);

    cy.get('input[name="source"]').type("http://localhost:8001/example/idols");

    cy.get('input[name="httpProxiesCheck"]').click()

    cy.setCodeMirrorValue("#json-edit-field-httpProxies", '{"urlStart":"http://localhost:8001","httpProxy":"http://localhost:8000/"}, {"urlStart":"http://localhost:8002","httpProxy":"http://localhost:9000/"}]');

    cy.contains("Invalid HTTP proxies specification.");
    cy.get('input[name="httpProxiesCheck"]').click()
    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('input[name="httpProxiesCheck"]').click()
    cy.get('button[type="submit"]').click();
    cy.contains("Invalid HTTP proxies specification.");

    cy.setCodeMirrorValue("#json-edit-field-httpProxies", '[{"urlStart":"http://localhost:8001","httpProxy":"http://localhost:8000/"}, {"urlStart":"http://localhost:8002","httpProxy":"http://localhost:9000/"}]');

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    // Check if the query works
    cy.contains("1-2 of 2");

    // Check if updating the custom query results in changed results - here we just change the httpProxies details to point to a not existing proxy, resulting in Comunica failing to fetch
    cy.get('button').contains("Edit Query").click();

    cy.setCodeMirrorValue("#json-edit-field-httpProxies", '[{"urlStart":"http://localhost:8001","httpProxy":"http://localhost:9999/"}, {"urlStart":"http://localhost:8002","httpProxy":"http://localhost:9000/"}]');

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    cy.contains("Something went wrong").should('exist');
  });

  it("Check if all possible parameters are filled in with parameterized URL", () => {
    // Navigate to the URL of a saved query with completely filled-in form
    cy.visit("/#/customQuery?name=Query+Name&description=Query+Description&queryString=Sparql+query+text&comunicaContextCheck=on&source=The+Comunica+Source&comunicaContext=%7B%22Advanced+Comunica+Context%22%3Atrue%7D&sourceIndexCheck=on&indexSourceUrl=Index+Source&indexSourceQuery=Index+Query+&askQueryCheck=on&askQuery=%7B%22trueText%22%3A%22+filled+in%22%2C%22falseText%22%3A%22not+filled+in%22%7D&directVariablesCheck=on&variables=%7B%22firstvariables%22%3A%5B%22only+one%22%5D%7D&httpProxiesCheck=on&httpProxies=%5B%7B%22urlStart%22%3A%22http%3A%2F%2Flocalhost%3A8001%22%2C%22httpProxy%22%3A%22http%3A%2F%2Flocalhost%3A8000%2F%22%7D%5D")

    // Verify that every field is correctly filled-in
    cy.get('input[name="name"]').should('have.value', 'Query Name');
    cy.get('textarea[name="description"]').should('have.value', 'Query Description');

    cy.checkCodeMirrorValue("#sparql-edit-field-queryString", 'Sparql query text');

    cy.get('input[name="source"]').should('have.value', "The Comunica Source");
    cy.checkCodeMirrorValue("#json-edit-field-comunicaContext", `{"Advanced Comunica Context":true}`);

    cy.get('input[name="indexSourceUrl"]').should('have.value', "Index Source");
    cy.checkCodeMirrorValue("#sparql-edit-field-indexSourceQuery", "Index Query ");

    cy.checkCodeMirrorValue("#json-edit-field-askQuery", `{"trueText":" filled in","falseText":"not filled in"}`);

    cy.checkCodeMirrorValue("#json-edit-field-httpProxies", `[{"urlStart":"http://localhost:8001","httpProxy":"http://localhost:8000/"}]`);

    cy.checkCodeMirrorValue("#json-edit-field-variables", `{"firstvariables":["only one"]}`);

    // The first error
    cy.contains("Invalid SPARQL query.");
  });

  it("Shares the correct URL", () => {
    cy.visit("/#/customQuery");

    // First create a simple query
    cy.get('input[name="name"]').type("new query");
    cy.get('textarea[name="description"]').type("new description");

    cy.setCodeMirrorValue("#sparql-edit-field-queryString", `PREFIX schema: <http://schema.org/> 
SELECT * WHERE {
    ?list schema:name ?listTitle;
      schema:itemListElement [
      schema:name ?bookTitle;
      schema:creator [
        schema:name ?authorName
      ]
    ].
}`);
    
    cy.get('input[name="source"]').type("http://localhost:8080/example/wish-list");

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    cy.get('button').contains("Share Query").click();

    cy.get('textarea[name="queryURL"]').invoke('val').then((val) => {
      expect(orderedUrl(val)).to.equal(orderedUrl(Cypress.config('baseUrl') + '#/customQuery?name=new+query&description=new+description&queryString=PREFIX+schema%3A+%3Chttp%3A%2F%2Fschema.org%2F%3E+%0ASELECT+*+WHERE+%7B%0A++++%3Flist+schema%3Aname+%3FlistTitle%3B%0A++++++schema%3AitemListElement+%5B%0A++++++schema%3Aname+%3FbookTitle%3B%0A++++++schema%3Acreator+%5B%0A++++++++schema%3Aname+%3FauthorName%0A++++++%5D%0A++++%5D.%0A%7D&source=http%3A%2F%2Flocalhost%3A8080%2Fexample%2Fwish-list'));
    });
  });

  it("Custom templated query", () => {
    cy.visit("/#/customQuery");

    cy.get('input[name="name"]').type("custom template");
    cy.get('textarea[name="description"]').type("description for template");

    // Query handling a variable
    cy.setCodeMirrorValue("#sparql-edit-field-queryString", `PREFIX schema: <http://schema.org/>
SELECT ?name ?sameAs_url WHERE {
  ?list schema:name ?listTitle;
    schema:name ?name;
    schema:genre $genre;
    schema:sameAs ?sameAs_url;
}`
    );

    cy.get('input[name="source"]').type("http://localhost:8080/example/favourite-musicians");
    cy.get('input[name="directVariablesCheck"]').click()

    cy.setCodeMirrorValue("#json-edit-field-variables", `{
        "genre": [
          "\\"Romantic\\"",
          "\\"Baroque\\"",
          "\\"Classical\\""
    }`)

    cy.contains("Invalid fixed templated variables specification.");
    cy.get('input[name="directVariablesCheck"]').click()
    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('input[name="directVariablesCheck"]').click()
    cy.get('button[type="submit"]').click();
    cy.contains("Invalid fixed templated variables specification.");

    cy.setCodeMirrorValue("#json-edit-field-variables", `{
      "genre": [
        "\\"Romantic\\"",
        "\\"Baroque\\"",
        "\\"Classical\\""
      ]
    }`)

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    cy.get('.ra-input-genre').click();
    cy.get('li').contains('Baroque').click();
    cy.get('button[type="submit"]').click();

    cy.get('.column-name').find('span').contains("Antonio Caldara").should('exist');
  });

  it("Custom Query With Index File", () => {
    cy.visit("/#/customQuery");

    cy.get('input[name="name"]').type("custom with index file");
    cy.get('textarea[name="description"]').type("description for index");

    // Query handling a variable
    cy.setCodeMirrorValue("#sparql-edit-field-queryString", `# Query Texon's components and their materials
# Datasources: https://css5.onto-deside.ilabt.imec.be/texon/data/dt/out/components.ttl https://css5.onto-deside.ilabt.imec.be/texon/data/dt/out/boms.ttl https://css5.onto-deside.ilabt.imec.be/texon/data/dt/out/materials.ttl

PREFIX oo: <http://purl.org/openorg/>
PREFIX ao: <http://purl.org/ontology/ao/core#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX d: <https://www.example.com/data/>
PREFIX o: <https://www.example.com/ont/>

SELECT ?component ?componentName ?material ?materialName ?percentage
WHERE {
  ?component
    a o:Component ;
    o:name ?componentName ;
    o:has-component-bom [
      o:has-component-material-assoc [
        o:percentage ?percentage ;
        o:has-material ?material ;
      ];
    ];
  .
  ?material o:name ?materialName ;
}
ORDER BY ?componentName`
    );

    // No Comunica Sources Required
    cy.get('input[name="sourceIndexCheck"]').click()
    cy.get('input[name="indexSourceUrl"]').type("http://localhost:8080/example/index-example-texon-only")

    cy.setCodeMirrorValue("#sparql-edit-field-indexSourceQuery", "this is not a valid SPARQL query")

    cy.contains("Invalid indirect sources SPARQL query.");
    cy.get('input[name="sourceIndexCheck"]').click()
    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('input[name="sourceIndexCheck"]').click()
    cy.get('button[type="submit"]').click();
    cy.contains("Invalid indirect sources SPARQL query.");

    cy.setCodeMirrorValue("#sparql-edit-field-indexSourceQuery", `PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX example: <http://localhost:8080/example/index-example-texon-only#>

SELECT ?object
WHERE {
  example:index-example rdfs:seeAlso ?object .
}`
    )

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    cy.contains("https://www.example.com/data/component-c01").should('exist');

    // Check if updating the custom query results in changed results - here we just change the indexSourceUrl, resulting in Comunica failing to fetch
    cy.get('button').contains("Edit Query").click();

    cy.get('input[name="indexSourceUrl"]').clear();
    cy.get('input[name="indexSourceUrl"]').type("http://localhost:8080/example/huppledepup-does-not-exist")

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    cy.contains("The result list is empty (no sources found).").should('exist');
  });

  it("Make a templated query, then edit it to make it a normal query", () => {
    cy.visit("/#/customQuery");

    cy.get('input[name="name"]').type("custom template");
    cy.get('textarea[name="description"]').type("description for template");

    // Query handling a variable
    cy.setCodeMirrorValue("#sparql-edit-field-queryString", `PREFIX schema: <http://schema.org/>
      SELECT ?name ?sameAs_url WHERE {
        ?list schema:name ?listTitle;
          schema:name ?name;
          schema:genre $genre;
          schema:sameAs ?sameAs_url;
      }`
    );

    cy.get('input[name="source"]').type("http://localhost:8080/example/favourite-musicians");
    cy.get('input[name="directVariablesCheck"]').click()

    cy.setCodeMirrorValue("#json-edit-field-variables", `{
          "genre": [
            "\\"Romantic\\"",
            "\\"Baroque\\"",
            "\\"Classical\\""
          ]
      }`)

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    cy.get('.ra-input-genre').click();
    cy.get('li').contains('Baroque').click();
    cy.get('button[type="submit"]').click();

    cy.get('.column-name').find('span').contains("Antonio Caldara").should('exist');

    // Now that this templated one works, lets edit it to make a normal query from it
    cy.get('button').contains("Edit Query").click();

    cy.setCodeMirrorValue("#sparql-edit-field-queryString", `PREFIX schema: <http://schema.org/>
  SELECT ?name ?genre ?sameAs_url WHERE {
    ?list schema:name ?listTitle;
      schema:name ?name;
      schema:genre ?genre;
      schema:sameAs ?sameAs_url;
  }`
    );

    // Remove the templated options
    cy.get('input[name="directVariablesCheck"]').click()

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    cy.get('form').should('not.exist')

    cy.get('.column-name').find('span').contains("Ludwig van Beethoven").should('exist');
  });

  // Reverse logic

  it("Make a normal query, then edit it to make it a templated query", () => {
    cy.visit("/#/customQuery");

    cy.get('input[name="name"]').type("custom template");
    cy.get('textarea[name="description"]').type("description for template");

    // Query handling a variable
    cy.setCodeMirrorValue("#sparql-edit-field-queryString", `PREFIX schema: <http://schema.org/>
      SELECT ?name ?genre ?sameAs_url WHERE {
        ?list schema:name ?listTitle;
          schema:name ?name;
          schema:genre ?genre;
          schema:sameAs ?sameAs_url;
      }`
    );

    cy.get('input[name="source"]').type("http://localhost:8080/example/favourite-musicians");

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    cy.get('form').should('not.exist')

    cy.get('.column-name').find('span').contains("Ludwig van Beethoven").should('exist');

    // Now that this normal one works, lets edit it to make a templated query from it
    cy.get('button').contains("Edit Query").click();

    cy.setCodeMirrorValue("#sparql-edit-field-queryString", `PREFIX schema: <http://schema.org/>
  SELECT ?name ?sameAs_url WHERE {
    ?list schema:name ?listTitle;
      schema:name ?name;
      schema:genre $genre;
      schema:sameAs ?sameAs_url;
  }`
    );

    cy.get('input[name="directVariablesCheck"]').click()

    cy.setCodeMirrorValue("#json-edit-field-variables", `{
          "genre": [
            "\\"Romantic\\"",
            "\\"Baroque\\"",
            "\\"Classical\\""
          ]
      }`)

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    cy.get('.ra-input-genre').click();
    cy.get('li').contains('Baroque').click();
    cy.get('button[type="submit"]').click();

    cy.get('.column-name').find('span').contains("Antonio Caldara").should('exist');
  });

  it("Custom templated query with 1 indirect variable", () => {
    cy.visit("/#/customQuery");

    cy.get('input[name="name"]').type("custom indirect template");
    cy.get('textarea[name="description"]').type("description for an indirect templated query");

    // Query handling a variable
    cy.setCodeMirrorValue("#sparql-edit-field-queryString", `PREFIX schema: <http://schema.org/>
SELECT ?name ?sameAs_url WHERE {
?list schema:name ?listTitle;
schema:name ?name;
schema:genre $genre;
schema:sameAs ?sameAs_url;
}`
    );

    cy.get('input[name="source"]').type("http://localhost:8080/example/favourite-musicians");
    cy.get('input[name="indirectVariablesCheck"]').click()

    cy.setCodeMirrorValue("#sparql-edit-field-indirectVariablesQuery-0", "PREFIX schema: <http://schema.org/> SELECT DISTINCT ?genre WHERE { ?list schema:genre ?genre; }")

    // Test the bad SPARQL syntax on a second indirect variable query
    cy.get('button').contains("Add another query").click();
    cy.setCodeMirrorValue("#sparql-edit-field-indirectVariablesQuery-1", "this is not a valid SPARQL query")

    cy.contains("Invalid SPARQL query to retrieve variable(s) from source(s).");
    cy.get('input[name="indirectVariablesCheck"]').click()
    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('input[name="indirectVariablesCheck"]').click()
    cy.get('button[type="submit"]').click();
    cy.contains("Invalid SPARQL query to retrieve variable(s) from source(s).");

    // Deleting the second indirect variable query should also clear the error status
    cy.get('[data-testid="DeleteIcon"]').last().click();

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    cy.get('.ra-input-genre').click();
    cy.get('li').contains('Baroque').click();
    cy.get('button[type="submit"]').click();

    cy.get('.column-name').find('span').contains("Antonio Caldara").should('exist');
    cy.get('.column-name').find('span').contains("Pietro Locatelli").should('exist');

    cy.get('.column-name').find('span').contains("Franz Schubert").should("not.exist");
    cy.get('.column-name').find('span').contains("Ludwig van Beethoven").should("not.exist");

    // Check if updating the custom query results in changed results - here we just change the first indirectVariablesQuery
    cy.get('button').contains("Edit Query").click();

    cy.setCodeMirrorValue("#sparql-edit-field-indirectVariablesQuery-0", "PREFIX schema: <http://schema.org/> SELECT DISTINCT ?geEEEnre WHERE { ?list schema:genre ?geEEEnre; }")

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    cy.get('.ra-input-geEEEnre').should('exist');
  });

  it("Custom templated query with 2 indirect variables", () => {
    cy.visit("/#/customQuery");

    cy.get('input[name="name"]').type("custom indirect template 2");
    cy.get('textarea[name="description"]').type("description for an indirect templated query 2");

    // Query handling a variable
    cy.setCodeMirrorValue("#sparql-edit-field-queryString", `PREFIX schema: <http://schema.org/>
SELECT ?name WHERE {
?list schema:name ?listTitle;
schema:name ?name;
schema:genre $genre;
schema:sameAs $sameAsUrl;
}`
    );

    cy.get('input[name="source"]').type("http://localhost:8080/example/favourite-musicians");
    cy.get('input[name="indirectVariablesCheck"]').click()

    cy.setCodeMirrorValue("#sparql-edit-field-indirectVariablesQuery-0", "PREFIX schema: <http://schema.org/> SELECT DISTINCT ?genre WHERE { ?list schema:genre ?genre; }")
    cy.get('button').contains("Add another query").click();
    cy.setCodeMirrorValue("#sparql-edit-field-indirectVariablesQuery-1", "PREFIX schema: <http://schema.org/> SELECT DISTINCT ?sameAsUrl WHERE { ?list schema:sameAs ?sameAsUrl; }")

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();
    // Run some testcases now

    // Existing combination (only Mozart)
    cy.get('.ra-input-genre').click();
    cy.get('li').contains('Classical').click();
    cy.get('.ra-input-sameAsUrl').click();
    cy.get('li').contains('Mozart').click();
    cy.get('button[type="submit"]').click();

    cy.contains("Finished in:");
    cy.get('.column-name').find('span').contains("Wolfgang Amadeus Mozart").should("exist");

    cy.get('.column-name').find('span').contains("Franz Schubert").should("not.exist");
    cy.get('.column-name').find('span').contains("Johann Sebastian Bach").should("not.exist");
    cy.get('.column-name').find('span').contains("Ludwig van Beethoven").should("not.exist");

    // Change variables and make an unexisting combination
    cy.get('button').contains("Change Variables").should("exist");
    cy.get('button').contains("Change Variables").click();

    cy.get('.ra-input-genre').click();
    cy.get('li').contains('Baroque').click();
    cy.get('.ra-input-sameAsUrl').click();
    cy.get('li').contains('Beethoven').click();
    cy.get('button[type="submit"]').click();

    cy.get('span').contains("The result list is empty.").should("exist");

    // Change variables and make another existing combination
    cy.get('button').contains("Change Variables").should("exist");
    cy.get('button').contains("Change Variables").click();

    cy.get('.ra-input-genre').click();
    cy.get('li').contains('Romantic').click();
    cy.get('.ra-input-sameAsUrl').click();
    cy.get('li').contains('Schubert').click();
    cy.get('button[type="submit"]').click();

    cy.get('span').contains("The result list is empty.").should("not.exist");
    cy.get('.column-name').find('span').contains("Ludwig van Beethoven").should("not.exist");
    cy.get('.column-name').find('span').contains("Johann Sebastian Bach").should("not.exist");
    cy.get('.column-name').find('span').contains("Antonio Vivaldi").should("not.exist");
    cy.get('.column-name').find('span').contains("Franz Schubert").should("exist");
  });

  it("Make a custom templated query with 1 indirect variable and edit into a query with 2 indirect variables", () => {
    cy.visit("/#/customQuery");

    cy.get('input[name="name"]').type("custom indirect template");
    cy.get('textarea[name="description"]').type("description for an indirect templated query");
    cy.setCodeMirrorValue("#sparql-edit-field-queryString", `PREFIX schema: <http://schema.org/>
SELECT ?name ?sameAs_url WHERE {
?list schema:name ?listTitle;
schema:name ?name;
schema:genre $genre;
schema:sameAs ?sameAs_url;
}`);
    cy.get('input[name="source"]').type("http://localhost:8080/example/favourite-musicians");
    cy.get('input[name="indirectVariablesCheck"]').click()

    cy.setCodeMirrorValue("#sparql-edit-field-indirectVariablesQuery-0", "PREFIX schema: <http://schema.org/> SELECT DISTINCT ?genre WHERE { ?list schema:genre ?genre; }")

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    // Check if the query works
    cy.get('.ra-input-genre').click();
    cy.get('li').contains('Baroque').click();
    cy.get('button[type="submit"]').click();

    cy.get('.column-name').find('span').contains("Antonio Caldara").should('exist');
    cy.get('.column-name').find('span').contains("Franz Schubert").should("not.exist");

    // Now edit the query into one with 2 variables
    cy.get('button').contains("Edit Query").click();

    // Check if the values are correctly filled in
    cy.get('input[name="name"]').should('have.value', 'custom indirect template');

    // Now change the query
    cy.setCodeMirrorValue("#sparql-edit-field-queryString", `PREFIX schema: <http://schema.org/>
SELECT ?name WHERE {
?list schema:name ?listTitle;
schema:name ?name;
schema:genre $genre;
schema:sameAs $sameAsUrl;
}`
    );

    // add source for the second variable
    cy.get('button').contains("Add another query").click();
    cy.setCodeMirrorValue("#sparql-edit-field-indirectVariablesQuery-1", "PREFIX schema: <http://schema.org/> SELECT DISTINCT ?sameAsUrl WHERE { ?list schema:sameAs ?sameAsUrl; }")

    // The changes are done, now submit it
    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    // Try an existing combination
    cy.get('.ra-input-genre').click();
    cy.get('li').contains('Classical').click();
    cy.get('.ra-input-sameAsUrl').click();
    cy.get('li').contains('Beethoven').click();
    cy.get('button[type="submit"]').click();

    cy.contains("Finished in:");
    cy.get('.column-name').find('span').contains("Ludwig van Beethoven").should("exist");
    cy.get('.column-name').find('span').contains("Wolfgang Amadeus Mozart").should("not.exist");
  });

  it("Custom templated query with 1 indirect variable and sources from an index file", () => {
    cy.visit("/#/customQuery");

    cy.get('input[name="name"]').type("custom indirect template with index");
    cy.get('textarea[name="description"]').type("description for an indirect templated query and index sources");

    // Query handling a variable
    cy.setCodeMirrorValue("#sparql-edit-field-queryString", `PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX o: <https://www.example.com/ont/>

SELECT ?componentName ?materialName ?percentage ?component  ?material
WHERE {
  {
    ?component
      a o:Component ;
      o:name ?componentName ;
      o:has-component-bom [
        o:has-component-material-assoc [
          o:percentage ?percentage ;
          o:has-material ?material ;
        ];
      ];
    .
    ?material o:name ?materialName
  }
  FILTER(?componentName = $componentName)
}
ORDER BY ?componentName`);


    cy.get('input[name="sourceIndexCheck"]').click()
    cy.get('input[name="indexSourceUrl"]').type("http://localhost:8080/example/index-example-texon-only")

    cy.setCodeMirrorValue("#sparql-edit-field-indexSourceQuery", `PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX example: <http://localhost:8080/example/index-example-texon-only#>

SELECT ?object
WHERE {
  example:index-example rdfs:seeAlso ?object .
}`);

    cy.get('input[name="indirectVariablesCheck"]').click()

    cy.setCodeMirrorValue("#sparql-edit-field-indirectVariablesQuery-0", `PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX o: <https://www.example.com/ont/>

SELECT DISTINCT ?componentName
WHERE {
  ?component
    o:name ?componentName ;
	o:has-component-bom ?bom
}
ORDER BY ?componentName`)

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    cy.get('.ra-input-componentName').click();
    cy.get('li').contains('Component 1').click();
    cy.get('button[type="submit"]').click();

    // Check that it is correctly loaded with and only the correct data appears
    cy.contains("Finished in:");

    cy.get('.column-componentName').find('span').contains("Component 1").should("exist");
    cy.get('.column-materialName').find('span').contains("Material 2").should("exist");
    cy.get('.column-materialName').find('span').contains("Material 1").should("exist");

    cy.get('.column-componentName').find('span').contains("Component 2").should("not.exist");
    cy.get('.column-componentName').find('span').contains("Component 3").should("not.exist");
    cy.get('.column-materialName').find('span').contains("Material 6").should("not.exist");
  });

  it("Custom templated query with 2 indirect variables and sources from an index file", () => {
    cy.visit("/#/customQuery");

    cy.get('input[name="name"]').type("custom indirect template with index");
    cy.get('textarea[name="description"]').type("description for an indirect templated query and index sources");

    // Query handling a variable
    cy.setCodeMirrorValue("#sparql-edit-field-queryString", `PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX o: <https://www.example.com/ont/>

SELECT ?component ?componentName ?material ?materialName ?percentage
WHERE {
  {
    ?component
      a o:Component ;
      o:name ?componentName ;
      o:has-component-bom [
        o:has-component-material-assoc [
          o:percentage ?percentage ;
          o:has-material ?material ;
        ];
      ];
    .
    ?material o:name ?materialName
  }
  FILTER(?componentName = $componentName && ?materialName = $materialName)
}
ORDER BY ?componentName
`);

    cy.get('input[name="sourceIndexCheck"]').click()
    cy.get('input[name="indexSourceUrl"]').type("http://localhost:8080/example/index-example-texon-only")

    cy.setCodeMirrorValue("#sparql-edit-field-indexSourceQuery", `PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX example: <http://localhost:8080/example/index-example-texon-only#>

SELECT ?object
WHERE {
  example:index-example rdfs:seeAlso ?object .
}`);

    cy.get('input[name="indirectVariablesCheck"]').click()

    cy.setCodeMirrorValue("#sparql-edit-field-indirectVariablesQuery-0", `PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX o: <https://www.example.com/ont/>

SELECT DISTINCT ?componentName
WHERE {
  ?component
    o:name ?componentName ;
	o:has-component-bom ?bom
}
ORDER BY ?componentName`)

    cy.get('button').contains("Add another query").click();

    cy.setCodeMirrorValue("#sparql-edit-field-indirectVariablesQuery-1", `PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX o: <https://www.example.com/ont/>

SELECT DISTINCT ?materialName
WHERE {
  ?componentMaterialAssoc o:has-material [
    o:name ?materialName
  ]
}
ORDER BY ?materialName`)

    cy.get('[data-cy="parsingError"]').should('not.exist');
    cy.get('button[type="submit"]').click();

    cy.get('.ra-input-componentName').click();
    cy.get('li').contains('Component 1').click();
    cy.get('.ra-input-materialName').click();
    cy.get('li').contains('Material 2').click();
    cy.get('button[type="submit"]').click();

    // Check that it is correctly loaded with and only the correct data appears
    cy.contains("Finished in:");

    cy.get('.column-componentName').find('span').contains("Component 1").should("exist");
    cy.get('.column-materialName').find('span').contains("Material 2").should("exist");

    cy.get('.column-materialName').find('span').contains("Material 1").should("not.exist");
    cy.get('.column-componentName').find('span').contains("Component 2").should("not.exist");
    cy.get('.column-componentName').find('span').contains("Component 3").should("not.exist");
    cy.get('.column-materialName').find('span').contains("Material 6").should("not.exist");
  });
});