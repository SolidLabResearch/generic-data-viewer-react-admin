describe("Customize existing query", () => {

  it("simple query", () => {
    cy.visit("/");
    cy.contains("Example queries").click();
    cy.contains("A public list of books I'd love to own").click();

    cy.get('button').contains("Clone as custom query").click();

    cy.url().should('include', 'customQuery');


    cy.get('input[name="name"]').should('have.value', "(Cloned from) A public list of books I'd love to own");

    cy.checkCodeMirrorValue("#sparql-edit-field-queryString", `PREFIX schema: <http://schema.org/> 

SELECT * WHERE {
    ?list schema:name ?listTitle;
      schema:itemListElement [
      schema:name ?bookTitle;
      schema:creator [
        schema:name ?authorName
      ]
    ].
}`);

    cy.get('input[name="source"]').should('have.value', "http://localhost:8080/example/wish-list");

  })

  it("templated query - fixed variables", () => {
    cy.visit("/");
    cy.contains("Example queries").click();
    cy.contains("A templated query about musicians").click();

    cy.get('.ra-input-genre').click();
    cy.get('li').contains('Baroque').click();

    cy.get('button[type="submit"]').click();

    cy.get('button').contains("Clone as custom query").click();
    cy.url().should('include', 'customQuery');

    cy.get('input[name="name"]').should('have.value', "(Cloned from) A templated query about musicians");

    cy.checkCodeMirrorValue("#sparql-edit-field-queryString", `PREFIX schema: <http://schema.org/>

SELECT ?name ?sameAs_url WHERE {
  ?list schema:name ?listTitle;
    schema:name ?name;
    schema:genre $genre;
    schema:sameAs ?sameAs_url;
}`);

    cy.checkCodeMirrorValue("#json-edit-field-variables", `{"genre":["\\"Romantic\\"","\\"Baroque\\"","\\"Classical\\""]}`)





  })

  it("templated query - indirect variables", () => {

    cy.visit("/");
    cy.contains("For testing only").click();
    cy.contains("A templated query about musicians, two variables (indirect variables)").click();

    cy.get('.ra-input-genre').click();
    cy.get('li').contains('Baroque').click();

    cy.get('.ra-input-sameAsUrl').click();
    cy.get('li').contains('Vivaldi').click();

    cy.get('button[type="submit"]').click();

    cy.get('button').contains("Clone as custom query").click();
    cy.url().should('include', 'customQuery');

    cy.get('input[name="name"]').should('have.value', "(Cloned from) A templated query about musicians, two variables (indirect variables)");

    cy.checkCodeMirrorValue("#sparql-edit-field-queryString", `PREFIX schema: <http://schema.org/>

SELECT ?name WHERE {
  ?list schema:name ?listTitle;
    schema:name ?name;
    schema:genre $genre;
    schema:sameAs $sameAsUrl;
}
`);

    cy.checkCodeMirrorValue("#sparql-edit-field-indirectVariablesQuery-0", `PREFIX schema: <http://schema.org/> 

SELECT DISTINCT ?genre
WHERE {
  ?list schema:genre ?genre
}
ORDER BY ?genre
`);

    cy.checkCodeMirrorValue("#sparql-edit-field-indirectVariablesQuery-1", `PREFIX schema: <http://schema.org/> 

SELECT DISTINCT ?sameAsUrl
WHERE { 
  ?list schema:sameAs ?sameAsUrl
}
ORDER BY ?sameAsUrl
`);




  })

  it("index file", () => {
    cy.visit("/");
    cy.contains("Example queries").click();
    cy.contains("Sources from an index file").click();

    cy.get('button').contains("Clone as custom query").click({ force: true }); // Button is out of FoV so we gotta force the click

    cy.url().should('include', 'customQuery');


    cy.get('input[name="name"]').should('have.value', "(Cloned from) Sources from an index file");

    cy.checkCodeMirrorValue("#sparql-edit-field-queryString", `PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
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
ORDER BY ?componentName
`);

    cy.get('input[name="indexSourceUrl"]').should('have.value', `http://localhost:8080/example/index-example-texon-only-lt`)
    cy.checkCodeMirrorValue("#sparql-edit-field-indexSourceQuery", `PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT DISTINCT ?source WHERE {
  ?s rdfs:seeAlso ?source.
}
`)

  })

  it("ASK query", () => {
    cy.visit("/");
    cy.contains("Example queries").click();
    cy.contains("Is there an artist influenced by Picasso?").click();

    cy.get('button').contains("Clone as custom query").click({ force: true }); // Button is out of FoV so we gotta force the click

    cy.url().should('include', 'customQuery');

    cy.checkCodeMirrorValue("#json-edit-field-askQuery", `{"trueText":"Yes, there is at least one artist influenced by Picasso!","falseText":"No, there is not a single artist influenced by Picasso."}`);
  })

  it("http proxies", () => {
    cy.visit("/");
    cy.contains("Example queries").click();
    cy.contains("My idols").click();

    cy.get('button').contains("Clone as custom query").click({ force: true }); // Button is out of FoV so we gotta force the click

    cy.url().should('include', 'customQuery');

    cy.checkCodeMirrorValue("#json-edit-field-httpProxies", `[{"urlStart":"http://localhost:8001","httpProxy":"http://localhost:8000/"}]`);
  })

})

describe("Clone and customize existing query, clone the custom after", () => {

  it("clone simple query", () => {
    cy.visit("/");
    cy.contains("Example queries").click();
    cy.contains("A public list of books I'd love to own").click();

    cy.get('button').contains("Clone as custom query").click();

    cy.url().should('include', 'customQuery');


    cy.get('input[name="name"]').should('have.value', "(Cloned from) A public list of books I'd love to own");

    cy.checkCodeMirrorValue("#sparql-edit-field-queryString", `PREFIX schema: <http://schema.org/> 

SELECT * WHERE {
    ?list schema:name ?listTitle;
      schema:itemListElement [
      schema:name ?bookTitle;
      schema:creator [
        schema:name ?authorName
      ]
    ].
}`
    );
    cy.get('input[name="source"]').should('have.value', "http://localhost:8080/example/wish-list");

    cy.get('button[type="submit"]').click();

    cy.contains("Colleen Hoover").should("exist");

    cy.get('button').contains("Clone").click();

    cy.url().should('include', 'customQuery');


    cy.get('input[name="name"]').should('have.value', "(Cloned) (Cloned from) A public list of books I'd love to own");

  })
})