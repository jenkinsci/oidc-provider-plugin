/*
 * The MIT License
 *
 * Copyright 2022 CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package io.jenkins.plugins.oidc_provider;

import hudson.Extension;
import hudson.Util;
import hudson.model.AbstractItem;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.model.ModelObject;
import hudson.model.Run;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.StaplerRequest2;
import org.springframework.security.access.AccessDeniedException;

/**
 * Issuer scoped to a folder with credentials defined (directly) there.
 */
public final class FolderIssuer extends Issuer {

    private final ItemGroup<?> folder;

    private FolderIssuer(ItemGroup<?> folder) {
        this.folder = folder;
    }

    @Override protected ModelObject context() {
        return folder;
    }

    /**
     * Usually the same as {@link AbstractItem#getUrl} (with leading rather than trailing slash)
     * but ignores “current” view as well as unusual {@link ItemGroup#getUrlChildPrefix}s.
     * (In practice there are no overrides of the latter whose children could be folders.)
     */
    @Override protected String uri() {
        return Stream.of(folder.getFullName().split("/")).map(Util::rawEncode).collect(Collectors.joining("/job/", "/job/", ""));
    }

    @Override protected void checkExtendedReadPermission() throws AccessDeniedException {
        ((Item) folder).checkPermission(Item.READ);
    }

    @Extension public static final class Factory implements Issuer.Factory {

        @Override public Issuer forUri(String uri) {
            if (uri.matches("(/job/[^/]+)+")) {
                Item folder = Jenkins.get().getItemByFullName(URI.create(uri.substring(5).replace("/job/", "/")).getPath());
                if (folder instanceof ItemGroup) {
                    return new FolderIssuer((ItemGroup<?>) folder);
                }
            }
            return null;
        }

        @Override public Collection<? extends Issuer> forContext(Run<?, ?> context) {
            List<FolderIssuer> issuers = new ArrayList<>();
            for (ItemGroup<?> folder = context.getParent().getParent(); folder instanceof Item; folder = ((Item) folder).getParent()) {
                issuers.add(new FolderIssuer(folder));
            }
            return issuers;
        }

        @Override public Issuer forConfig(StaplerRequest2 req) {
            ItemGroup<?> folder = req.findAncestorObject(ItemGroup.class);
            return folder instanceof Item ? new FolderIssuer(folder) : null;
        }

    }

}
