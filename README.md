# Generic Data Viewer React Admin

This Web app allows users to easily execute queries over multiple data sources (including Solid pods) and
inspect the corresponding results.

## Getting Started

After installing, the following steps suffice to install the application:

```bash
npm install
```

after this you can execute

```bash
npm run dev
```

Which will start the web application

## Static build

If you want a static build of the application execute

```bash
npm run build
```

This will create a static build in the `dist` folder.

### Logging in

To log in you need to provide an Identity Provider or a WebID.
The application will detect which one you use and redirect you to the login page of your Identity Provider.
If you use your WebID, the first OIDC issuer on your WebID is used when there are multiple.

### Configuration file

The configuration file follows a simple structure.

```js
{
    "title": "Title shown at the top of the app.",
    "logoLocation": "Image location of the logo shown at the top of the app (relative to public folder.).",
    "logoRedirectURL": "The URL the Web application redirects to when a user clicks on the logo.",
    "mainAppColor": "The main colors used in the app, can be any CSS color.",
    "backgroundColor": "Background color of the app, can be any CSS color.",
    "titleColor": "The color of the title, can be any CSS color",
    "textColor": "The color of all the text in teh app body, this means all text except header and footer.",
    "footer": "HTML components or text that will function as the footer (will be placed in the footer div.)",
    "defaultIDP": "The default value used for IDP when logging in, this IDP can be manually changed in the Web app as well. ",
    "queryFolder": "The base location of the queries, all query locations will start from this folder (relative to public folder.)",
    "httpProxy": "The http proxy through which the requests will be rerouted. When left empty, the Comunica query engine will handle it. This is useful when CORS headers are not set (correctly) on the queried source.",
    "introductionText": "The text that the app shows on the dashboard, which the app also shows when you first open it.",
    "queries": [
        {
            "queryLocation": "path to the query location, relative to "queryFolder"",
            "name": "A name for the query",
            "description": "Description of the query",
            "id": "A unique ID for the query",
            "icon" "The key to the icon for to represent the query, see below. This is optional and a default menu icon will be used when left empty.",
            "comunicaContext": {
                "sources": "Sources over which the query should be executed",
                "useProxy": "True or false, whether the query should be executed through the proxy or not. This field is optional and defaults to false.",
                ...{"any other field that can be used in the Comunica query engine https://comunica.dev/docs/query/advanced/context/"}
          },
            },
            "askQuery": {
                "trueText": "The text that is to be shown when the query result is true, only useful for ASK queries.",
                "falseText": "The text that is to be shown when the query result is true, only useful for ASK queries."
            }

        }
        ...
    ]
}
```

### Adding variable type

When executing a query, it gives us either a URL, a literal value or [a blank node](https://www.w3.org/TR/rdf12-concepts/#section-blank-nodes).
These URLs could reference to anything e.g. a picture, spreadsheet, resume, and so on.
Also literals can be lots of things e.g. a float, integer, string, birthdate, price, and so on.
By clarifying what the expected type is of the query result corresponding to a given variable
we can fully interpret how we can display and represent the result.

You can specify the type of a variable by extending its name with the type in the query as such: `variableName_variableType`.
The underscore `_` here is crucial to make a clear distinction between name and type.

### Icon Mapper

In the selection menu the name of the query is proceeded by an icon.
You configure this icon per query in the [configuration file](#configuration-file).  
For this to work you need to add the icon to the [IconMapper.js](./src/IconProvider/IconProvider.js) file.
We advice to use the [Material UI icons](https://material-ui.com/components/material-icons/) as this is what's used internally in `react-admin` and it is also included in the dependencies.
Nevertheless, you can use any React component you want, just make sure it's a functional component.

The mapper follows the following structure:

```js
{
    "iconName": iconComponent,
    ...
}
```

### Representation Mapper

If you want to add your own type representations
you can do this by adding your representation to the
[typeMapper.js](./src/representationProvider/representationProvider.jsx) file.
This can be useful for example when querying images.
The result of the query is a reference to the image.
By mapping a representation we can show the actual image instead of the reference.

The mapper follows a structure:

```js
{
    "typeName": mapperComponent,
    ...
}
```

With `typeName` being the name of the variable as defined in the `query`
which is defined in [the configuration file](#configuration-file).
The function `mapperComponent` takes the query result for the corresponding variable and
returns either a [React](https://react.dev/) component (see below).
Examples of how you can do this can already be found in the [representationProvider/components folder](./src/representationProvider/components/).

The components get the following props:

- `record` (the query result), an object of `RDF/JS` objects.
- `variable` the variable name and key of `record`, a string.

`Hint` use the [Field components](https://marmelab.com/react-admin/doc/3.19/Fields.html#basic-fields)
from `react-admin` to display the result.
They've already got styling matching that of `react-admin` and are easy to use.

`Warning` if you change the record object, the changed will still be present in the next render.

## Testing with local pods

To create a local pod with which you can test for example authentication you can follow the following steps:

- Add your data and `.acl` files in the `initial-pod-data` folder.
  These files will be available in the pod relative to `http://localhost:8080/example/`.
  We already added files for the resource `favourite-books`.
- Prepare the pods by executing `npm run prepare:pods`.
- Start the pods by executing `npm run start:pods`.
- Add your query as described in [the configuration file section](#configuration-file).
  We already added a query to list books based on the resource `favourite-books` to `src/config.json`.
- Log in with the IDP `http://localhost:8080` and
  the credentials in the file `seeded-pod-config.json`.

## Using a local http proxy

To use a local http proxy through which the requests will be rerouted execute the following command:

```bash
npm run start:proxy
```

which will start a proxy on port `8000`.

## Testing

For testing we use [Cypress](https://www.cypress.io/).

1. Prepare and start the Community Solid Server with the available pods as explained in the [Testing with local pods section](#testing-with-local-pods).

   ```bash
   npm run prepare:pods && npm run start:pods
   ```

   Keep the server running.

2. Start the Web application

   ```bash
   npm run dev
   ```

   Also keep this process running.
3. Start the http proxy

   ```bash
   npm run start:proxy
   ```

4. Start a server which denies all cors header

   ```bash
   npm run start:badCors
   ```

   This process must also be active throughout the tests.

5. Finally, you can execute the tests by running

   ```bash
   npm run test
   ```
