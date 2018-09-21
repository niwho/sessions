package sessions

import (
	"fmt"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/niwho/chains"
)

func AuthRequered(loaders *chains.DataLoaderManager, cookeID string, loginUri string, keyPairs ...[]byte) gin.HandlerFunc {

	store := NewMultiStore(loaders, keyPairs...)
	return func(c *gin.Context) {
		session, _ := store.Get(c.Request, cookeID)
		c.Set("session", session)
		_, found := session.GetInt("user_id")
		if !found {
			// 重定向
			c.Redirect(302, fmt.Sprintf("%s%s/%s/?next=%s", c.Request.URL.Scheme, c.Request.Host, loginUri, url.QueryEscape(c.Request.URL.RequestURI())))
			return
		}
	}
}

func AuthOptional(loaders *chains.DataLoaderManager, cookeID string, keyPairs ...[]byte) gin.HandlerFunc {

	store := NewMultiStore(loaders, keyPairs...)
	return func(c *gin.Context) {
		session, _ := store.Get(c.Request, cookeID)
		c.Set("session", session)
	}
}
