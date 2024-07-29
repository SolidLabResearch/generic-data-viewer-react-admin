describe("Indirect variable query", () => {

    it("Indirect with 1 variable", () => {

        cy.visit("/");
        cy.contains("General examples").click();
        cy.contains("A templated query about musicians (indirect variables)").click();

        // Fill in the form
        cy.get('form').within(() => {
            cy.get('#genre').click();
        });
        cy.get('li').contains('Baroque').click();

        // Comfirm query
        cy.get('button').contains('Query').click();

        // Check that the page loaded and that we can see the correct data
        cy.contains("Finished in:");
        cy.get('.column-name').find('span').contains("Johann Sebastian Bach").should("exist");;
        cy.get('.column-name').find('span').contains("Marc-Antoine Charpentier").should("exist");;
        // Check that we don't see artists that don't belong here
        cy.get('.column-name').find('span').contains("Franz Schubert").should("not.exist");
        cy.get('.column-name').find('span').contains("Wolfgang Amadeus Mozart").should("not.exist");

    });

    it("Indirect with 2 variables", () => {

        cy.visit("/");
        cy.contains("For testing only").click();
        cy.contains("A templated query about musicians, two variables (indirect variables)").click();

        // Fill in the form
        cy.get('form').within(() => {
            cy.get('#genre').click();
        });
        cy.get('li').contains('Classical').click();

        cy.get('form').within(() => {
            cy.get('#sameAsUrl').click();
        });
        cy.get('li').contains('Mozart').click();

        cy.get('button').contains('Query').click();

        // Check that it is correctly loaded with and only the correct data appears
        cy.contains("Finished in:");
        cy.get('.column-name').find('span').contains("Wolfgang Amadeus Mozart").should("exist");;

        cy.get('.column-name').find('span').contains("Franz Schubert").should("not.exist");
        cy.get('.column-name').find('span').contains("Johann Sebastian Bach").should("not.exist");
        cy.get('.column-name').find('span').contains("Ludwig van Beethoven").should("not.exist");

    });

    it("Custom indirect query with 1 variable", () => {

        // Create the indirect variable
        cy.visit("/#/customQuery");

        cy.get('input[name="name"]').type("custom indirect template");
        cy.get('textarea[name="description"]').type("description for an indirect templated query");

        // Query handling a variable
        cy.get('textarea[name="queryString"]').clear();
        cy.get('textarea[name="queryString"]').type(`PREFIX schema: <http://schema.org/>
SELECT ?name ?sameAs_url WHERE {
  ?list schema:name ?listTitle;
    schema:name ?name;
    schema:genre $genre;
    schema:sameAs ?sameAs_url;
}`
        );

        cy.get('input[name="source"]').type("http://localhost:8080/example/favourite-musicians");
        cy.get('input[name="templatedQueryCheck"]').click()

        cy.get('textarea[name="templateOptions"]').clear()
        cy.get('textarea[name="templateOptions"]').type(`{
     "indirectVariables": {
          "queryStrings": [
               "PREFIX schema: <http://schema.org/> SELECT DISTINCT ?genre WHERE { ?list schema:genre ?genre; }"
          ]
     }
}`, {parseSpecialCharSequences: false} )
        cy.get('button[type="submit"]').click();


        cy.get('form').within(() => {
            cy.get('#genre').click();
        });
        cy.get('li').contains('Baroque').click();

        // Comfirm query
        cy.get('button[type="submit"]').click();

        cy.get('.column-name').find('span').contains("Antonio Caldara").should('exist');
        cy.get('.column-name').find('span').contains("Pietro Locatelli").should('exist');

        cy.get('.column-name').find('span').contains("Franz Schubert").should("not.exist");
        cy.get('.column-name').find('span').contains("Ludwig van Beethoven").should("not.exist");


    });

    it("Custom indirect query with 2 variables", () => {

        // Create the indirect variable
        cy.visit("/#/customQuery");

        cy.get('input[name="name"]').type("custom indirect template 2");
        cy.get('textarea[name="description"]').type("description for an indirect templated query 2");

        // Query handling a variable
        cy.get('textarea[name="queryString"]').clear();
        cy.get('textarea[name="queryString"]').type(`PREFIX schema: <http://schema.org/>
SELECT ?name WHERE {
  ?list schema:name ?listTitle;
    schema:name ?name;
    schema:genre $genre;
    schema:sameAs $sameAsUrl;
}`
        );

        cy.get('input[name="source"]').type("http://localhost:8080/example/favourite-musicians");
        cy.get('input[name="templatedQueryCheck"]').click()

        cy.get('textarea[name="templateOptions"]').clear()
        cy.get('textarea[name="templateOptions"]').type(`{ "indirectVariables": {
         "queryStrings": [
              "PREFIX schema: <http://schema.org/> SELECT DISTINCT ?genre WHERE { ?list schema:genre ?genre; }",
              "PREFIX schema: <http://schema.org/> SELECT DISTINCT ?sameAsUrl WHERE { ?list schema:sameAs ?sameAsUrl; }"
         ]
    }
}`, {parseSpecialCharSequences: false} )
        cy.get('button[type="submit"]').click();

        // Run some testcases now


        // Existing combination (only Mozart)
        cy.get('form').within(() => {
            cy.get('#genre').click();
        });
        cy.get('li').contains('Classical').click();

        cy.get('form').within(() => {
            cy.get('#sameAsUrl').click();
        });
        cy.get('li').contains('Mozart').click();

        cy.get('button[type="submit"]').click();


        cy.contains("Finished in:");
        cy.get('.column-name').find('span').contains("Wolfgang Amadeus Mozart").should("exist");;

        cy.get('.column-name').find('span').contains("Franz Schubert").should("not.exist");
        cy.get('.column-name').find('span').contains("Johann Sebastian Bach").should("not.exist");
        cy.get('.column-name').find('span').contains("Ludwig van Beethoven").should("not.exist");

        // Change variables and make an unexisting combination
        cy.get('button').contains("Change Variables").should("exist");
        cy.get('button').contains("Change Variables").click();

        cy.get('form').within(() => {
            cy.get('#genre').click();
        });
        cy.get('li').contains('Baroque').click();

        cy.get('form').within(() => {
            cy.get('#sameAsUrl').click();
        });
        cy.get('li').contains('Beethoven').click();

        cy.get('button[type="submit"]').click();

        cy.get('span').contains("The result list is empty.").should("exist");
        cy.get('.column-name').find('span').contains("Ludwig van Beethoven").should("not.exist");
        cy.get('.column-name').find('span').contains("Wolfgang Amadeus Mozart").should("not.exist");;


        // Change variables and make another existing combination

        cy.get('button').contains("Change Variables").should("exist");
        cy.get('button').contains("Change Variables").click();

        cy.get('form').within(() => {
            cy.get('#genre').click();
        });
        cy.get('li').contains('Romantic').click();

        cy.get('form').within(() => {
            cy.get('#sameAsUrl').click();
        });
        cy.get('li').contains('Schubert').click();

        cy.get('button[type="submit"]').click();

        cy.get('span').contains("The result list is empty.").should("not.exist");
        cy.get('.column-name').find('span').contains("Ludwig van Beethoven").should("not.exist");
        cy.get('.column-name').find('span').contains("Johann Sebastian Bach").should("not.exist");
        cy.get('.column-name').find('span').contains("Antonio Vivaldi").should("not.exist");
        cy.get('.column-name').find('span').contains("Franz Schubert").should("exist");


    });


});



