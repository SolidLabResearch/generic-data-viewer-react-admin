
describe("Simple Custom Query Editor tests", () => {

    it("Create a new query and successfully create the URLparams", () => {

        cy.visit("/#/customQuery");

        cy.get('input[name="name"]').type("new query");
        cy.get('textarea[name="description"]').type("new description");
        cy.get('textarea[name="queryString"]').type(`PREFIX schema: <http://schema.org/> 

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
        cy.get('button[type="submit"]').click();

        // Search Params were correctly created
        cy.url().should('include', '?name=new+query&description=new+description&queryString=PREFIX+schema%3A+%3Chttp%3A%2F%2Fschema.org%2F%3E+%0A%0ASELECT+*+WHERE+%7B%0A++++%3Flist+schema%3Aname+%3FlistTitle%3B%0A++++++schema%3AitemListElement+%5B%0A++++++schema%3Aname+%3FbookTitle%3B%0A++++++schema%3Acreator+%5B%0A++++++++schema%3Aname+%3FauthorName%0A++++++%5D%0A++++%5D.%0A%7D&source=http%3A%2F%2Flocalhost%3A8080%2Fexample%2Fwish-list')

        cy.contains("Custom queries").click();
        cy.contains("new query").click();

        // Checking if the book query works
        cy.contains("Colleen Hoover").should('exist');
    });

    it("Create a new query, with multiple sources", () => {

        cy.visit("/#/customQuery");

        cy.get('input[name="name"]').type("material query");
        cy.get('textarea[name="description"]').type("this query has 3 sources");
        cy.get('textarea[name="queryString"]').type(`# Query Texon's components
# Datasources: https://css5.onto-deside.ilabt.imec.be/texon/data/dt/out/components.ttl

PREFIX oo: <http://purl.org/openorg/>
PREFIX ao: <http://purl.org/ontology/ao/core#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX d: <http://www/example.com/data/>
PREFIX o: <http://www/example.com/ont/>

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
        cy.get('button[type="submit"]').click();
    
        cy.contains("Custom queries").click();
        cy.contains("material query").click();

        // Checking if the query works
        cy.contains("http://www/example.com/data/component-c01").should('exist');
    });

    it("Check if all possible parameters are filled in with parameterized URL", () => { 

        // Navigate to the URL of a saved query with completely filled-in form
        cy.visit("/#/customQuery?name=Query+Name&description=Query+Description&queryString=Sparql+query+text&comunicaContextCheck=on&source=The+Comunica+Source&comunicaContext=%7B%22Advanced+Comunica+Context%22%3Atrue%7D&sourceIndexCheck=on&indexSourceUrl=Index+Source&indexSourceQuery=Index+Query+&askQueryCheck=on&askQuery=%7B%22trueText%22%3A%22+filled+in%22%2C%22falseText%22%3A%22not+filled+in%22%7D&templatedQueryCheck=on&variables=%7B%22firstvariables%22%3A%5B%22only+one%22%5D%7D")
        
        // Verify that every field is correctly filled-in
        cy.get('input[name="name"]').should('have.value', 'Query Name');
        cy.get('textarea[name="description"]').should('have.value','Query Description');
        cy.get('textarea[name="queryString"]').should('have.value','Sparql query text');

        cy.get('input[name="source"]').should('have.value',"The Comunica Source");
        cy.get('textarea[name="comunicaContext"]').should('have.value',`{"Advanced Comunica Context":true}`);

        cy.get('input[name="indexSourceUrl"]').should('have.value',"Index Source"); 
        cy.get('textarea[name="indexSourceQuery"]').should('have.value',"Index Query ");

        cy.get('textarea[name="askQuery"]').should('have.value',`{"trueText":" filled in","falseText":"not filled in"}`);

        cy.get('textarea[name="variables"]').should('have.value',`{"firstvariables":["only one"]}`);

    })

    it( "Successfully edit a query to make it work" , () => {

        cy.visit("/#/customQuery");
        
        // First create a wrong query
        cy.get('input[name="name"]').type("broken query");
        cy.get('textarea[name="description"]').type("just a description");

        cy.get('textarea[name="queryString"]').type("this is faultive querytext")
       
        cy.get('input[name="source"]').type("http://localhost:8080/example/wish-list");

        //Submit the faultive query
        cy.get('button[type="submit"]').click();

        cy.contains("Custom queries").click();
        cy.contains("broken query").click();

        // Verify that there are no results
        cy.contains("The result list is empty.").should('exist');
        
        // Edit the query
        cy.get('button').contains("Edit Query").click();

        // Give the query a new name and a correct query text
        cy.get('input[name="name"]').clear();
        cy.get('input[name="name"]').type("Fixed query");

        cy.get('textarea[name="queryString"]').clear();
        cy.get('textarea[name="queryString"]').type(`PREFIX schema: <http://schema.org/> 

            SELECT * WHERE {
                ?list schema:name ?listTitle;
                  schema:itemListElement [
                  schema:name ?bookTitle;
                  schema:creator [
                    schema:name ?authorName
                  ]
                ].
            }`);

        // Submit the correct query
        cy.get('button[type="submit"]').click();

        // Now we should be on the page of the fixed query
        cy.contains("Fixed query").should('exist');

        // Check if the resulting list appears
        cy.contains("Colleen Hoover").should('exist');

    })

    it("Saves the correct URL", ()=>{

        cy.visit("/#/customQuery");

        // First create a simple query
        cy.get('input[name="name"]').type("new query");
        cy.get('textarea[name="description"]').type("new description");
        cy.get('textarea[name="queryString"]').type(`PREFIX schema: <http://schema.org/> 

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
        cy.get('button[type="submit"]').click();

        // Search Params were correctly created
        cy.url().should('include', '?name=new+query&description=new+description&queryString=PREFIX+schema%3A+%3Chttp%3A%2F%2Fschema.org%2F%3E+%0A%0ASELECT+*+WHERE+%7B%0A++++%3Flist+schema%3Aname+%3FlistTitle%3B%0A++++++schema%3AitemListElement+%5B%0A++++++schema%3Aname+%3FbookTitle%3B%0A++++++schema%3Acreator+%5B%0A++++++++schema%3Aname+%3FauthorName%0A++++++%5D%0A++++%5D.%0A%7D&source=http%3A%2F%2Flocalhost%3A8080%2Fexample%2Fwish-list')
        
        // Remember the URL
        cy.url().then((url) => {
            cy.wrap(url).as('createdUrl');
        });

        // Now go to the query and save it
        cy.contains("Custom queries").click();
        cy.contains("new query").click();
        cy.get('button').contains("Save Query").click();

        // The given URL is correct
        cy.get('@createdUrl').then((createdUrl) => {
            cy.get('textarea[name="queryURL"]').should('have.value', createdUrl);
          });
    })

    // NOG EEN TEMPLATED TEST


    // NOG EEN INDEX FILE TEST
})